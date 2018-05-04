#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/common/types.h"

static struct fake {
	int junk;
} dummy;

struct sk_buff *skb_out = NULL;

struct config_candidate *cfgcandidate_alloc(void)
{
	return (struct config_candidate *)&dummy;
}

void cfgcandidate_get(struct config_candidate *candidate)
{
	/* No code. */
}

void cfgcandidate_put(struct config_candidate *candidate)
{
	/* No code. */
}

verdict sendpkt_send(struct xlation *state)
{
	log_debug("Pretending I'm sending a packet.");
	skb_out = state->out.skb;
	return VERDICT_CONTINUE;
}
