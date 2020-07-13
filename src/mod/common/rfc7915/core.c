#include "mod/common/rfc7915/core.h"

#include "mod/common/log.h"
#include "mod/common/rfc7915/4to6.h"
#include "mod/common/rfc7915/6to4.h"

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
	struct translation_steps const *steps;
	verdict result;

	switch (xlator_get_type(&state->jool)) {
	case XT_NAT64:
		log_debug(state, "Step 4: Translating the Packet");
		break;
	case XT_SIIT:
		log_debug(state, "Translating the Packet.");
		break;
	}

	switch (pkt_l3_proto(&state->in)) {
	case L3PROTO_IPV6:
		steps = &ttp64_steps;
		break;
	case L3PROTO_IPV4:
		steps = &ttp46_steps;
		break;
	default:
		WARN(1, "Unknown l3 proto: %u", pkt_l3_proto(&state->in));
		return drop(state, JSTAT_UNKNOWN);
	}

	result = steps->skb_alloc(state);
	if (result != VERDICT_CONTINUE)
		return result;
	result = steps->xlat_outer_l3(state);
	if (result != VERDICT_CONTINUE)
		goto revert;
	if (has_l4_hdr(state)) {
		result = xlat_l4_function(state, steps);
		if (result != VERDICT_CONTINUE)
			goto revert;
	}

	if (xlation_is_nat64(state))
		log_debug(state, "Done step 4.");
	return VERDICT_CONTINUE;

revert:
	kfree_skb_list(state->out.skb);
	return result;
}
