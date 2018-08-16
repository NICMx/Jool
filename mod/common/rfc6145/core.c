#include "nat64/mod/common/rfc6145/core.h"

#include "nat64/mod/common/rfc6145/common.h"

static bool has_l4_hdr(struct xlation *state)
{
	switch (pkt_l3_proto(&state->in)) {
	case L3PROTO_IPV6:
		return is_first_frag6(pkt_frag_hdr(&state->in));
	case L3PROTO_IPV4:
		return is_first_frag4(pkt_ip4_hdr(&state->in));
	}

	WARN(1, "Supposedly unreachable code reached. Proto: %u",
			pkt_l3_proto(&state->in));
	return false;
}

verdict translating_the_packet(struct xlation *state)
{
	struct translation_steps *steps = ttpcomm_get_steps(&state->in);
	verdict result;

	if (xlat_is_nat64())
		log_debug("Step 4: Translating the Packet");
	else
		log_debug("Translating the Packet.");

	result = steps->skb_alloc_fn(state);
	if (result != VERDICT_CONTINUE)
		return result;

	result = steps->l3_hdr_fn(state);
	if (result != VERDICT_CONTINUE)
		goto revert;

	if (has_l4_hdr(state)) {
		result = steps->l4_hdr_fn(state);
		if (result != VERDICT_CONTINUE)
			goto revert;
	}

	if (xlat_is_nat64())
		log_debug("Done step 4.");
	return VERDICT_CONTINUE;

revert:
	kfree_skb(state->out.skb);
	return result;
}
