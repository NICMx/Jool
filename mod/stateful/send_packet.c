#include "nat64/mod/stateful/send_packet.h"

#include <linux/icmp.h>
#include <net/ipv6.h>

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/icmp_wrapper.h"


static const unsigned int HDRS_LEN = sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);


/**
 * Caution: fragments created by this function will have unset header pointers.
 */
static struct sk_buff *create_skb_frag(struct sk_buff *breaking_skb, unsigned int payload_len)
{
	struct sk_buff *result_skb;

	result_skb = alloc_skb(LL_MAX_HEADER /* kernel's reserved + layer 2. */
			+ HDRS_LEN /* l3 header. */
			+ payload_len, /* packet data. */
			GFP_ATOMIC);
	if (!result_skb) {
		inc_stats(breaking_skb, IPSTATS_MIB_FRAGFAILS);
		return NULL;
	}

	skb_reserve(result_skb, LL_MAX_HEADER + HDRS_LEN);
	skb_put(result_skb, payload_len);

	result_skb->protocol = breaking_skb->protocol;
	result_skb->mark = breaking_skb->mark;

	skb_set_jcb(result_skb, L3PROTO_IPV6, skb_l4_proto(breaking_skb), true,
			result_skb->data,
			skb_original_skb(breaking_skb));

	return result_skb;
}

/**
 * Fragments "skb" by sending its surplus to new skbs. The surplus is defined by "trim_len" and
 * "payload_mtu".
 *
 * The resulting fragments are appended to skb's list (skb->next);
 * skb_shinfo(skb)->frag_list is ignored because this function is convoluted enough as it is.
 * Calling code needs to fix this.
 *
 * Assumes any skbs involved lack a fragment header and aren't paged.
 *
 * @param trim_len if skb's length is larger than trim_len, skb will be truncated to trim_len.
 * @param payload_mtu maximum allowable length for skb's layer 3 payload.
 *
 * "trim_len" and "payload_mtu" are separated because the kernel handles the lengths of first and
 * subsequent fragments differently.
 */
static int divide(struct sk_buff *skb, unsigned int trim_len, unsigned int payload_mtu)
{
	unsigned char *current_ptr;
	struct sk_buff *prev_skb;

	if (skb_headlen(skb) <= trim_len)
		return 0;

	/* Copy frag's overweight to newly-created fragments. */
	prev_skb = skb;
	current_ptr = skb->data + trim_len;
	do {
		bool is_last = (skb_tail_pointer(skb) - current_ptr) <= payload_mtu;
		unsigned int payload_len = is_last ? (skb_tail_pointer(skb) - current_ptr) : payload_mtu;
		struct sk_buff *new_skb;

		new_skb = create_skb_frag(skb, payload_len);
		if (!new_skb)
			return -ENOMEM;
		memcpy(new_skb->data, current_ptr, payload_len);

		new_skb->next = prev_skb->next;
		prev_skb->next = new_skb;
		prev_skb = new_skb;

		current_ptr += payload_len;
		inc_stats(skb, IPSTATS_MIB_FRAGCREATES);
	} while (current_ptr < skb_tail_pointer(skb));

	/* Truncate the original packet. */
	skb_set_tail_pointer(skb, trim_len);

	inc_stats(skb, IPSTATS_MIB_FRAGOKS);
	return 0;
}

/**
 * Might actually trim to a slightly smaller length than new_len, because I need to align new_len,
 * otherwise the checksum update will be a mess.
 * (csum_partial() seems to require the start of the data to be aligned to a 32-bit boundary.)
 *
 * **skb MUST be linearized**
 */
static int icmp6_trim(struct sk_buff *skb, unsigned int new_len)
{
	struct icmp6hdr *hdr = icmp6_hdr(skb);
	__wsum csum = ~csum_unfold(hdr->icmp6_cksum);
	__be16 tmp;

	/*
	 * "After the ethernet header, the protocol header will be aligned on at least a 4-byte
	 * boundary. Nearly all of the IPV4 and IPV6 protocol processing assumes that the headers are
	 * properly aligned." (http://vger.kernel.org/~davem/skb_data.html)
	 *
	 * Therefore, simply truncate the entire packet size to a multiple of 4.
	 */
	new_len = round_down(new_len, 4);
	if (new_len < sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)) {
		log_debug("I was asked to trim an illegally short packet.");
		return -EINVAL;
	}

	/* Substract the chunk we're truncating. */
	csum = csum_sub(csum, csum_partial(skb_network_header(skb) + new_len, skb->len - new_len, 0));
	/* Substract the difference of the "length" field from the pseudoheader. */
	tmp = cpu_to_be16(skb->len - new_len);
	csum = csum_sub(csum, csum_partial(&tmp, sizeof(tmp), 0));

	hdr->icmp6_cksum = csum_fold(csum);
	/* TODO (fine) There seems to be a problem with RFC 1624... review it later. This works. */
	if (hdr->icmp6_cksum == (__force __sum16) 0xFFFF)
		hdr->icmp6_cksum = 0;

	skb_trim(skb, new_len);
	ipv6_hdr(skb)->payload_len = cpu_to_be16(skb->len - sizeof(struct ipv6hdr));
	return 0;
}

static bool skb_is_icmp6_error(struct sk_buff *skb)
{
	return (skb_l4_proto(skb) == L4PROTO_ICMP) && is_icmp6_error(icmp6_hdr(skb)->icmp6_type);
}

static bool skb_is_icmp4_error(struct sk_buff *skb)
{
	return (skb_l4_proto(skb) == L4PROTO_ICMP) && is_icmp4_error(icmp_hdr(skb)->type);
}

static int reply_frag_needed(struct sk_buff *skb, unsigned int mtu)
{
	log_debug("Packet is too big (%u bytes; MTU: %u); dropping.", skb->len, mtu);
	icmp64_send(skb, ICMPERR_FRAG_NEEDED, mtu);
	inc_stats(skb, IPSTATS_MIB_INTOOBIGERRORS);
	return -EINVAL;
}

static unsigned int get_nexthop_mtu(struct sk_buff *skb)
{
#ifndef UNIT_TESTING
	return skb_dst(skb)->dev->mtu;
#else
	return 1500;
#endif
}

static void move_next_to_frag_list(struct sk_buff *skb)
{
	struct sk_buff *prev;
	struct sk_buff *tmp;

	if (!skb->next)
		return;

	for (tmp = skb->next; tmp; tmp = tmp->next) {
		skb->data_len += tmp->len;
		prev = tmp;
	}

	prev->next = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = skb->next;
	skb->next = NULL;
}

/* TODO test the kernel doesn't join fragments when min mtu6 < nexthop mtu. */
static int fragment_if_too_big(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	unsigned int mtu;
	int error;

	switch (skb_l3_proto(skb_out)) {
	case L3PROTO_IPV6: /* 4 to 6 */
		if (skb_is_icmp6_error(skb_out)) {
			mtu = config_get_min_mtu6();
			return (skb_out->len > mtu) ? icmp6_trim(skb_out, mtu) : 0;
		}

		if (is_dont_fragment_set(ip_hdr(skb_in))) {
			mtu = get_nexthop_mtu(skb_out);
			return (skb_len(skb_out) > mtu) ? reply_frag_needed(skb_out, mtu - 20) : 0;
		}

		mtu = config_get_min_mtu6();
		if (!skb_shinfo(skb_out)->frag_list && skb_out->len <= mtu)
			return 0;

		mtu &= 0xFFF8;
		error = divide(skb_out, mtu, mtu - HDRS_LEN);
		if (error) /* TODO rethink freeing? */
			return error;
		move_next_to_frag_list(skb_out);

		mtu -= HDRS_LEN; /* "mtu" is "l3 payload mtu" now. */
		skb_walk_frags(skb_out, skb_out) {
			error = divide(skb_out, mtu, mtu);
			if (error)
				return error;
		}

		return 0;

	case L3PROTO_IPV4: /* 6 to 4 */
		if (!skb_is_icmp4_error(skb_out) && is_dont_fragment_set(ip_hdr(skb_out))) {
			mtu = get_nexthop_mtu(skb_out);
			if (skb_out->len > mtu)
				return reply_frag_needed(skb_out, mtu + 20);
		}
		/* TODO test the kernel handles trimming and fragmentation fine. */
	}

	return 0;
}

verdict sendpkt_send(struct sk_buff *in_skb, struct sk_buff *out_skb)
{
	struct sk_buff *skb;
	struct dst_entry *dst;
	l3_protocol l3_proto;
	int error;

#ifdef BENCHMARK
	struct timespec end_time;
	getnstimeofday(&end_time);
	logtime(&skb_jcb(out_skb)->start_time, &end_time, skb_l3_proto(out_skb),
			skb_l4_proto(out_skb));
#endif

	if (WARN(!out_skb->dev, "Packet has no destination device."))
		goto fail;
	dst = skb_dst(out_skb);
	if (WARN(!dst, "Packet has no destination."))
		goto fail;
	if (WARN(!dst->dev, "Packet's destination has no device."))
		goto fail;

	error = fragment_if_too_big(in_skb, out_skb);
	if (error)
		goto fail;

	log_debug("Sending skb via device '%s'...", dst->dev->name);

	l3_proto = skb_l3_proto(out_skb);
	skb_clear_cb(out_skb);
	skb_walk_frags(out_skb, skb)
		skb_clear_cb(skb);

	/* TODO (issue #41) newer kernels don't have this. Review. */
	out_skb->local_df = true; /* FFS, kernel. */

	switch (l3_proto) {
	case L3PROTO_IPV6:
		error = ip6_local_out(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
		break;
	case L3PROTO_IPV4:
		error = ip_local_out(out_skb); /* Implicit kfree_skb(out_skb) goes here. */
		break;
	}

	if (error) {
		log_debug("The kernel's packet dispatch function returned errcode %d.", error);
		return VER_DROP;
	}

	return VER_CONTINUE;

fail:
	inc_stats(out_skb, IPSTATS_MIB_OUTDISCARDS);
	kfree_skb(out_skb);
	return VER_DROP;
}
