/* TODO (warning) read the erratas more (6145 and 6146). */

#include "nat64/mod/ttp/core.h"
#include "nat64/mod/ttp/common.h"
#include "nat64/mod/ttp/config.h"
#include "nat64/mod/icmp_wrapper.h"
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

static int copy_payload(struct pkt_parts *in, struct pkt_parts *out)
{
	memcpy(out->payload.ptr, in->payload.ptr, in->payload.len);
	return 0;
}

static verdict translate_fragment(struct tuple *tuple, struct sk_buff *in_skb,
		struct sk_buff **out_skb, struct dst_entry *dst)
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
		if (is_error(copy_payload(&in, &out)))
			goto fail;
	}
	if (dst) {
		skb_dst_set(out.skb, dst_clone(dst));
		out.skb->dev = dst->dev;
	} else {
		if (is_error(steps->route_fn(out.skb)))
			goto fail;
	}

	return VER_CONTINUE;

fail:
	kfree_skb_queued(*out_skb);
	*out_skb = NULL;
	return VER_DROP;
}

verdict translating_the_packet(struct tuple *out_tuple, struct sk_buff *in_skb,
		struct sk_buff **out_skb)
{
	verdict result;
	struct sk_buff *tmp_out_skb, *prev_out_skb, *next_in_skb;

	log_debug("Step 4: Translating the Packet");

	/* Translate the first fragment or a complete packet. */
	result = translate_fragment(out_tuple, in_skb, out_skb, NULL);
	if (result != VER_CONTINUE)
		return VER_DROP;

	next_in_skb = in_skb->next;
	prev_out_skb = *out_skb;
	while (prev_out_skb->next)
		prev_out_skb = prev_out_skb->next;

	/* If not a fragment, the next "while" will be omitted. */
	while (next_in_skb) {
		log_debug("Translating a Fragment Packet");
		result = translate_fragment(out_tuple, next_in_skb, &tmp_out_skb, skb_dst(*out_skb));
		if (result != VER_CONTINUE)
			goto fail;

		tmp_out_skb->prev = prev_out_skb;
		prev_out_skb->next = tmp_out_skb;

		while (tmp_out_skb->next)
			tmp_out_skb = tmp_out_skb->next;

		prev_out_skb = tmp_out_skb;
		next_in_skb = next_in_skb->next;
	}

	log_debug("Done step 4.");
	return VER_CONTINUE;
fail:
	kfree_skb_queued(*out_skb);
	*out_skb = NULL;
	return VER_DROP;
}
