/* TODO (warning) read the erratas more (6145 and 6146). */

#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/rfc6145/common.h"

static verdict translate_first(struct tuple *tuple, struct packet *in, struct packet *out)
{
	struct translation_steps *steps = ttpcomm_get_steps(pkt_l3_proto(in), pkt_l4_proto(in));
	verdict result;

	result = steps->skb_create_fn(in, out);
	if (result != VERDICT_CONTINUE)
		return result;
	result = steps->l3_hdr_fn(tuple, in, out);
	if (result != VERDICT_CONTINUE)
		goto revert;
	result = steps->l3_payload_fn(tuple, in, out);
	if (result != VERDICT_CONTINUE)
		goto revert;

	return result;

revert:
	kfree_skb(out->skb);
	return result;
}

static verdict translate_subsequent(struct packet *pkt_in, struct sk_buff *in,
		struct sk_buff **out)
{
	struct sk_buff *result;
	unsigned int hdrs_len = 0;
	__u16 proto = 0;
	int error;

	switch (pkt_l3_proto(pkt_in)) {
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
		inc_stats(pkt_in, IPSTATS_MIB_INDISCARDS);
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


verdict translating_the_packet(struct tuple *out_tuple, struct packet *in, struct packet *out)
{
	struct sk_buff *skb_in;
	struct sk_buff *skb_out = NULL;
	struct sk_buff *skb_prev = NULL;
	verdict result;

	if (xlat_is_nat64())
		log_debug("Step 4: Translating the Packet");
	else
		log_debug("Translating the Packet.");

	result = translate_first(out_tuple, in, out);
	if (result != VERDICT_CONTINUE)
		return result;

	skb_walk_frags(in->skb, skb_in) {
		log_debug("Translating a Fragment Packet");

		result = translate_subsequent(in, skb_in, &skb_out);
		if (result != VERDICT_CONTINUE) {
			kfree_skb(out->skb);
			return result;
		}

		if (!skb_prev)
			skb_shinfo(out->skb)->frag_list = skb_out;
		else
			skb_prev->next = skb_out;
		out->skb->len += skb_out->len;
		out->skb->data_len += skb_out->len;
		out->skb->truesize += skb_out->truesize;

		skb_prev = skb_out;
	}

	if (xlat_is_nat64())
		log_debug("Done step 4.");
	return VERDICT_CONTINUE;
}
