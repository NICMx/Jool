#include "nat64/mod/common/rfc6145/core.h"

#include "nat64/mod/common/rfc6145/common.h"

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
	result = steps->l3_payload_fn(state);
	if (result != VERDICT_CONTINUE)
		goto revert;

	if (xlat_is_nat64())
		log_debug("Done step 4.");
	return VERDICT_CONTINUE;

revert:
	kfree_skb(state->out.skb);
	return result;
}
