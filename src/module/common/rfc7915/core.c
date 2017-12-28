#include "rfc7915/core.h"

#include "icmp-wrapper.h"
#include "module-stats.h"
#include "rfc7915/common.h"

int translating_the_packet(struct xlation *state)
{
	struct translation_steps *steps = ttpcomm_get_steps(&state->in);
	int error;

	if (XLATOR_TYPE(state) == XLATOR_NAT64)
		log_debug("Step 4: Translating the Packet");
	else
		log_debug("Translating the Packet.");

	error = steps->skb_create_fn(state);
	if (error)
		return error;
	error = steps->l3_hdr_fn(state);
	if (error)
		goto revert;
	error = steps->l3_payload_fn(state);
	if (error)
		goto revert;

	if (XLATOR_TYPE(state) == XLATOR_NAT64)
		log_debug("Done step 4.");
	return 0;

revert:
	kfree_skb(state->out.skb);
	state->out.skb = NULL;
	return error;
}
