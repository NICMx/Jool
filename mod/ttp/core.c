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

static verdict translate_fragment(struct tuple *tuple, struct sk_buff *in, struct sk_buff **out,
		struct dst_entry *dst)
{
	struct translation_steps *steps = ttpcomm_get_steps(skb_l3_proto(in), skb_l4_proto(in));

	*out = NULL;

	if (is_error(steps->skb_create_fn(in, out)))
		goto fail;
	if (is_error(steps->l3_hdr_fn(tuple, in, *out)))
		goto fail;
	if (skb_has_l4_hdr(in)) {
		if (is_error(steps->l3_payload_fn(tuple, in, *out)))
			goto fail;
	} else {
		if (is_error(copy_payload(in, *out)))
			goto fail;
	}
	if (dst) {
		skb_dst_set(*out, dst_clone(dst));
		(*out)->dev = dst->dev;
	} else {
		if (is_error(steps->route_fn(*out)))
			goto fail;
	}

	return VER_CONTINUE;

fail:
	kfree_skb(*out);
	*out = NULL;
	return VER_DROP;
}

/*
 * TODO (issue #41) I haven't implemented IPv4 on kernels 3.13+, where the fragment list is stored
 * in frags, not frag_list.
 */
verdict translating_the_packet(struct tuple *out_tuple, struct sk_buff *in_skb,
		struct sk_buff **out_skb)
{
	struct sk_buff *current_out_skb, *prev_out_skb = NULL;
	verdict result;

	log_debug("Step 4: Translating the Packet");

	/* Translate the first fragment or a complete packet. */
	result = translate_fragment(out_tuple, in_skb, out_skb, NULL);
	if (result != VER_CONTINUE)
		return VER_DROP;

	/* If not a fragment, the next "while" will be omitted. */
	skb_walk_frags(in_skb, in_skb) {
		log_debug("Translating a Fragment Packet");
		result = translate_fragment(out_tuple, in_skb, &current_out_skb, skb_dst(*out_skb));
		if (result != VER_CONTINUE) {
			kfree_skb(*out_skb);
			*out_skb = NULL;
			return VER_DROP;
		}

		if (!prev_out_skb)
			skb_shinfo(*out_skb)->frag_list = current_out_skb;
		else
			prev_out_skb->next = current_out_skb;
		(*out_skb)->len += skb_payload_len_frag(current_out_skb);
		(*out_skb)->data_len += skb_payload_len_frag(current_out_skb);
		(*out_skb)->truesize += current_out_skb->truesize;

		prev_out_skb = current_out_skb;
	}

	log_debug("Done step 4.");
	return VER_CONTINUE;
}
