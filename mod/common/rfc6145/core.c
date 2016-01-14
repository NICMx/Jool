#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/rfc6145/common.h"

static verdict translate_first(struct xlation *state)
{
	struct translation_steps *steps = ttpcomm_get_steps(&state->in);
	verdict result;

	result = steps->skb_create_fn(state);
	if (result != VERDICT_CONTINUE)
		return result;
	result = steps->l3_hdr_fn(state);
	if (result != VERDICT_CONTINUE)
		goto revert;
	result = steps->l3_payload_fn(state);
	if (result != VERDICT_CONTINUE)
		goto revert;

	return result;

revert:
	kfree_skb(state->out.skb);
	return result;
}

static verdict translate_subsequent(struct xlation *state, struct sk_buff *in,
		struct sk_buff **out)
{
	struct sk_buff *result;
	unsigned int hdrs_len = 0;
	__u16 proto = 0;
	int error;

	switch (pkt_l3_proto(&state->in)) {
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
		inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}

	skb_reserve(result, LL_MAX_HEADER + hdrs_len);
	skb_put(result, in->len);
	result->mark = in->mark;
	result->protocol = htons(proto);

	error = skb_copy_bits(in, 0, result->data, in->len);
	if (error) {
		kfree_skb(result);
		log_debug("The payload copy threw errcode %d.", error);
		return VERDICT_DROP;
	}

	*out = result;
	return VERDICT_CONTINUE;
}


verdict translating_the_packet(struct xlation *state)
{
	struct sk_buff *skb_in;
	struct sk_buff *skb_out = NULL;
	struct sk_buff *skb_prev = NULL;
	verdict result;

	if (xlat_is_nat64())
		log_debug("Step 4: Translating the Packet");
	else
		log_debug("Translating the Packet.");

	result = translate_first(state);
	if (result != VERDICT_CONTINUE)
		return result;

	skb_walk_frags(state->in.skb, skb_in) {
		log_debug("Translating a Fragment Packet");

		result = translate_subsequent(state, skb_in, &skb_out);
		if (result != VERDICT_CONTINUE) {
			kfree_skb(state->out.skb);
			return result;
		}

		if (!skb_prev)
			skb_shinfo(state->out.skb)->frag_list = skb_out;
		else
			skb_prev->next = skb_out;
		state->out.skb->len += skb_out->len;
		state->out.skb->data_len += skb_out->len;
		state->out.skb->truesize += skb_out->truesize;

		skb_prev = skb_out;
	}

	if (xlat_is_nat64())
		log_debug("Done step 4.");
	return VERDICT_CONTINUE;
}
