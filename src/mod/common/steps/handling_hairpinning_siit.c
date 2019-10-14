#include "handling_hairpinning_siit.h"

#include "mod/common/log.h"
#include "mod/common/rfc7915/core.h"
#include "mod/common/steps/send_packet.h"

bool is_hairpin_siit(struct xlation *state)
{
	return pkt_is_intrinsic_hairpin(&state->out);
}

verdict handling_hairpinning_siit(struct xlation *old)
{
	struct xlation new;
	verdict result;

	log_debug("Packet is a hairpin. U-turning...");

	new.jool = old->jool;
	new.in = old->out;

	result = translating_the_packet(&new);
	if (result != VERDICT_CONTINUE)
		return result;
	result = sendpkt_send(&new);
	if (result != VERDICT_CONTINUE)
		return result;

	log_debug("Done hairpinning.");
	return VERDICT_CONTINUE;
}
