/* TODO (warning) read the erratas more (6145 and 6146). */

#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/rfc6145/common.h"

static verdict translate_first(struct tuple *tuple, struct sk_buff *in, struct sk_buff **out)
{
	struct translation_steps *steps = ttpcomm_get_steps(skb_l3_proto(in), skb_l4_proto(in));
	verdict result;

	*out = NULL;

	result = steps->skb_create_fn(in, out);
	if (result != VER_CONTINUE)
		goto fail;
	result = steps->l3_hdr_fn(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto fail;
	result = steps->l3_payload_fn(tuple, in, *out);
	if (result != VER_CONTINUE)
		goto fail;

	return VER_CONTINUE;

fail:
	kfree_skb(*out);
	*out = NULL;
	return result;
}

static verdict translate_subsequent(struct tuple *tuple, struct sk_buff *in, l3_protocol in_proto,
		struct sk_buff **out)
{
	struct sk_buff *result;
	unsigned int hdrs_len = 0;
	__u16 proto = 0;
	int error;

	switch (in_proto) {
	case L3PROTO_IPV6: /* out is IPv4. */
		hdrs_len = sizeof(struct iphdr);
		proto = ETH_P_IP;
		break;
	case L3PROTO_IPV4: /* out is IPv6. */
		hdrs_len = sizeof(struct ipv6hdr) + sizeof(struct frag_hdr);
		proto = ETH_P_IPV6;
		break;
	}

	result = alloc_skb(LL_MAX_HEADER + hdrs_len + in->len, GFP_ATOMIC);
	if (!result) {
		inc_stats(in, IPSTATS_MIB_INDISCARDS);
		return VER_DROP;
	}

	skb_reserve(result, LL_MAX_HEADER + hdrs_len);
	skb_put(result, in->len);
	result->mark = in->mark;
	result->protocol = htons(proto);

	error = skb_copy_bits(in, 0, result->data, in->len);
	if (error) {
		kfree_skb(result);
		log_debug("The payload copy threw errcode %d.", error);
		return VER_DROP;
	}

	*out = result;
	return VER_CONTINUE;
}

verdict translating_the_packet(struct tuple *out_tuple, struct sk_buff *in, struct sk_buff **out)
{
	struct sk_buff *in_frag;
	struct sk_buff *out_frag = NULL;
	struct sk_buff *out_prev = NULL;
	unsigned int payload_len;
	verdict result;

	if (nat64_is_stateful())
		log_debug("Step 4: Translating the Packet");
	else
		log_debug("Translating the Packet.");

	/* Translate the first fragment or a complete packet. */
	result = translate_first(out_tuple, in, out);
	if (result != VER_CONTINUE)
		return result;

	/* If not a fragment, the next "while" will be omitted. */
	skb_walk_frags(in, in_frag) {
		log_debug("Translating a Fragment Packet");

		result = translate_subsequent(out_tuple, in_frag, skb_l3_proto(in), &out_frag);
		if (result != VER_CONTINUE) {
			kfree_skb(*out);
			*out = NULL;
			return result;
		}

		if (!out_prev)
			skb_shinfo(*out)->frag_list = out_frag;
		else
			out_prev->next = out_frag;
		payload_len = skb_payload_len_frag(out_frag);
		(*out)->len += payload_len;
		(*out)->data_len += payload_len;
		(*out)->truesize += out_frag->truesize;

		out_prev = out_frag;
	}

	if (nat64_is_stateful())
		log_debug("Done step 4.");
	return VER_CONTINUE;
}
