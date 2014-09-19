/* TODO (warning) read the erratas more (6145 and 6146). */

#include "nat64/mod/ttp/core.h"
#include "nat64/mod/ttp/common.h"
#include "nat64/mod/ttp/config.h"
#include "nat64/mod/icmp_wrapper.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/stats.h"

int translate_packet_init(void)
{
	int error;

	error = ttpcomm_init();
	if (error)
		return error;

	error = ttpconfig_init();
	if (error)
		ttpcomm_destroy();

	return error;
}

void translate_packet_destroy(void)
{
	ttpconfig_destroy();
	ttpcomm_destroy();
}

int translate_clone_config(struct translate_config *clone)
{
	return ttpconfig_clone(clone);
}

int translate_set_config(enum translate_type type, size_t size, void *value)
{
	return ttpconfig_update(type, size, value);
}

static int skb_to_parts(struct sk_buff *skb, struct pkt_parts *parts)
{
	parts->l3_hdr.proto = skb_l3_proto(skb);
	parts->l3_hdr.len = skb_l3hdr_len(skb);
	parts->l3_hdr.ptr = skb_network_header(skb);
	parts->l4_hdr.proto = skb_l4_proto(skb);
	parts->l4_hdr.len = skb_l4hdr_len(skb);
	parts->l4_hdr.ptr = skb_transport_header(skb);
	parts->payload.len = skb_payload_len(skb);
	parts->payload.ptr = skb_payload(skb);
	parts->skb = skb;

	return 0;
}

static int copy_payload(struct tuple *tuple, struct pkt_parts *in, struct pkt_parts *out)
{
	memcpy(out->payload.ptr, in->payload.ptr, in->payload.len);
	return 0;
}

static void set_frag_headers(struct ipv6hdr *hdr6_old, struct ipv6hdr *hdr6_new,
		u16 packet_size, u16 offset, bool mf)
{
	struct frag_hdr *hdrfrag_old = (struct frag_hdr *) (hdr6_old + 1);
	struct frag_hdr *hdrfrag_new = (struct frag_hdr *) (hdr6_new + 1);

	if (hdr6_new != hdr6_old)
		memcpy(hdr6_new, hdr6_old, sizeof(*hdr6_new));
	hdr6_new->payload_len = cpu_to_be16(packet_size - sizeof(*hdr6_new));

	hdrfrag_new->nexthdr = hdrfrag_old->nexthdr;
	hdrfrag_new->reserved = 0;
	hdrfrag_new->frag_off = build_ipv6_frag_off_field(offset, mf);
	hdrfrag_new->identification = hdrfrag_old->identification;
}

/**
 * Fragments "frag" until all the pieces are at most "min_ipv6_mtu" bytes long.
 * "min_ipv6_mtu" comes from the user's configuration.
 * The resulting smaller fragments are appended to frag's list (frag->next).
 *
 * Assumes frag has a fragment header.
 * Also assumes the following fields from frag->skb are properly set: network_header, head, data
 * and tail.
 *
 * Sorry, this function is probably our most convoluted one, but everything in it is too
 * inter-related so I don't know how to fix it without creating thousand-argument functions.
 */
static int divide(struct sk_buff *skb, __u16 min_ipv6_mtu)
{
	unsigned char *current_p;
	struct sk_buff *new_skb;
	struct sk_buff *prev_skb;
	struct ipv6hdr *first_hdr6 = ipv6_hdr(skb);
	u16 hdrs_size;
	u16 payload_max_size;
	u16 original_fragment_offset;
	bool original_mf;

	/* Prepare the helper values. */
	min_ipv6_mtu &= 0xFFF8;

	hdrs_size = sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);
	payload_max_size = min_ipv6_mtu - hdrs_size;

	{
		struct frag_hdr *frag_header = (struct frag_hdr *) (first_hdr6 + 1);

		original_fragment_offset = get_fragment_offset_ipv6(frag_header);
		original_mf = is_more_fragments_set_ipv6(frag_header);
	}

	set_frag_headers(first_hdr6, first_hdr6, min_ipv6_mtu, original_fragment_offset, true);
	prev_skb = skb;

	/* Copy frag's overweight to newly-created fragments.  */
	current_p = skb_network_header(skb) + min_ipv6_mtu;
	while (current_p < skb_tail_pointer(skb)) {
		bool is_last = (skb_tail_pointer(skb) - current_p <= payload_max_size);
		u16 actual_payload_size = is_last
					? (skb_tail_pointer(skb) - current_p)
					: (payload_max_size & 0xFFF8);
		u16 actual_total_size = hdrs_size + actual_payload_size;

		new_skb = alloc_skb(LL_MAX_HEADER /* kernel's reserved + layer 2. */
				+ actual_total_size, /* l3 header + l4 header + packet data. */
				GFP_ATOMIC);
		if (!new_skb) {
			inc_stats(skb, IPSTATS_MIB_FRAGFAILS);
			return -ENOMEM;
		}

		skb_reserve(new_skb, LL_MAX_HEADER);
		skb_put(new_skb, actual_total_size);
		skb_reset_mac_header(new_skb);
		skb_reset_network_header(new_skb);
		skb_set_transport_header(new_skb, hdrs_size);
		new_skb->protocol = skb->protocol;
		new_skb->mark = skb->mark;

		set_frag_headers(first_hdr6, ipv6_hdr(new_skb), actual_total_size,
				original_fragment_offset + (current_p - skb->data - hdrs_size),
				is_last ? original_mf : true);
		memcpy(skb_network_header(new_skb) + hdrs_size, current_p, actual_payload_size);

		skb_set_jcb(new_skb, L3PROTO_IPV6, skb_l4_proto(skb),
				skb_transport_header(new_skb),
				(struct frag_hdr *) (ipv6_hdr(new_skb) + 1),
				skb_original_skb(skb));

		prev_skb->next = new_skb;
		new_skb->prev = prev_skb;

		current_p += actual_payload_size;
		prev_skb = new_skb;

		new_skb->next = NULL;
		inc_stats(skb, IPSTATS_MIB_FRAGCREATES);
	}

	/* Finally truncate the original packet and we're done. */
	skb_put(skb, -(skb->len - min_ipv6_mtu));
	inc_stats(skb, IPSTATS_MIB_FRAGOKS);
	return 0;
}

static int fragment_if_too_big(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	__u16 min_ipv6_mtu;

	/* TODO These logs should probably be debugs. */
	/* TODO Consider that this function also requires routed packets. */

	if (skb_l3_proto(skb_out) == L3PROTO_IPV4) {
#ifndef UNIT_TESTING
		__u16 min_ipv4_mtu = skb_dst(skb_out)->dev->mtu;
		if (is_dont_fragment_set(ip_hdr(skb_out)) && (skb_out->len > min_ipv4_mtu)) {
			icmp64_send(skb_out, ICMPERR_FRAG_NEEDED, min_ipv4_mtu + 20);
			log_info("Packet is too big (%u bytes; MTU: %u); dropping.", skb_out->len, min_ipv4_mtu);
			inc_stats(skb_out, IPSTATS_MIB_FRAGFAILS);
			return -EINVAL;
		}
#endif
		return 0; /* IPv4 routers fragment dandily, so let them do it. */
	}

	rcu_read_lock_bh();
	min_ipv6_mtu = ttpconfig_get()->min_ipv6_mtu;
	rcu_read_unlock_bh();

	if (skb_out->len <= min_ipv6_mtu)
		return 0; /* No need for fragmentation. */

	if (skb_l4_proto(skb_out) == L4PROTO_ICMP && is_icmp6_error(icmp6_hdr(skb_out)->icmp6_type)) {
		/*
		 * ICMP errors are supposed to be truncated, not fragmented.
		 * BTW: This corrupts the checksum, but that's fine since we're going to trash it in
		 * post_icmp6().
		 */
		skb_trim(skb_out, min_ipv6_mtu);
		ipv6_hdr(skb_out)->payload_len = cpu_to_be16(min_ipv6_mtu - sizeof(struct ipv6hdr));
		return 0;
	}

	if (is_dont_fragment_set(ip_hdr(skb_in))) {
		/* We're not supposed to fragment; yay. */
		icmp64_send(skb_in, ICMPERR_FRAG_NEEDED, min_ipv6_mtu - 20);
		log_info("Packet is too big (%u bytes; MTU: %u); dropping.", skb_out->len, min_ipv6_mtu);
		inc_stats(skb_in, IPSTATS_MIB_FRAGFAILS);
		return -EINVAL;
	}

	return divide(skb_out, min_ipv6_mtu);
}

static verdict translate_fragment(struct tuple *tuple, struct sk_buff *in_skb,
		struct sk_buff **out_skb)
{
	struct pkt_parts in;
	struct pkt_parts out;
	struct translation_steps *steps = ttpcomm_get_steps(skb_l3_proto(in_skb), skb_l4_proto(in_skb));

	*out_skb = NULL;

	if (is_error(skb_to_parts(in_skb, &in)))
		goto fail;
	if (is_error(steps->skb_create_fn(&in, out_skb)))
		goto fail;
	if (is_error(skb_to_parts(*out_skb, &out)))
		goto fail;
	if (is_error(steps->l3_hdr_fn(tuple, &in, &out)))
		goto fail;
	if (skb_has_l4_hdr(in_skb)) {
		if (is_error(steps->l3_payload_fn(tuple, &in, &out)))
			goto fail;
	} else {
		if (is_error(copy_payload(tuple, &in, &out)))
			goto fail;
	}

	if (is_error(fragment_if_too_big(in_skb, out.skb)))
		goto fail;

	return VER_CONTINUE;

fail:
	kfree_skb_queued(*out_skb);
	*out_skb = NULL;
	return VER_DROP;
}

static int route(struct sk_buff *skb)
{
	struct sk_buff *current_skb;
	int error = -EINVAL;

	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV6:
		error = route_ipv6(skb);
		break;
	case L3PROTO_IPV4:
		error = route_ipv4(skb);
		break;
	}

	if (error)
		return error;

	for (current_skb = skb->next; current_skb; current_skb = current_skb->next)
		skb_dst_set(current_skb, dst_clone(skb_dst(skb)));

	return 0;
}

verdict translating_the_packet(struct tuple *tuple, struct sk_buff *in_skb,
		struct sk_buff **out_skb)
{
	verdict result;
	struct sk_buff *tmp_out_skb, *prev_out_skb, *next_in_skb;
	int error;

	log_debug("Step 4: Translating the Packet");

	/* Translate the first fragment or a complete packet. */
	result = translate_fragment(tuple, in_skb, out_skb);
	if (result != VER_CONTINUE)
		return VER_DROP;

	next_in_skb = in_skb->next;
	prev_out_skb = *out_skb;
	while (prev_out_skb->next) {
		prev_out_skb = prev_out_skb->next;
	}

	/* If not a fragment, the next "while" will be omitted. */
	while (next_in_skb) {
		log_debug("Translating a Fragment Packet");
		result = translate_fragment(tuple, next_in_skb, &tmp_out_skb);
		if (result != VER_CONTINUE)
			goto fail;

		tmp_out_skb->prev = prev_out_skb;
		prev_out_skb->next = tmp_out_skb;

		while (tmp_out_skb->next) {
			tmp_out_skb = tmp_out_skb->next;
		}

		prev_out_skb = tmp_out_skb;
		next_in_skb = next_in_skb->next;
	}

	error = route(*out_skb);
	if (error)
		goto fail;

	log_debug("Done step 4.");
	return VER_CONTINUE;
fail:
	kfree_skb_queued(*out_skb);
	*out_skb = NULL;
	return VER_DROP;
}
