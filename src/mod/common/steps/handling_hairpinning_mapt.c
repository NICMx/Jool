#include "mod/common/steps/handling_hairpinning_mapt.h"

#include "mod/common/log.h"
#include "mod/common/db/fmr.h"
#include "mod/common/rfc7915/core.h"
#include "mod/common/steps/send_packet.h"

bool is_hairpin_mapt(struct xlation *state)
{
	int error;

	if (state->jool.globals.mapt.type != MAPTYPE_BR)
		return false;
	if (pkt_l3_proto(&state->in) != L3PROTO_IPV6)
		return false;

	error = fmrt_find4(state->jool.mapt.fmrt,
			pkt_ip4_hdr(&state->out)->daddr, NULL);
	switch (error) {
	case -ESRCH:
		return false;
	case 0:
		return true;
	}

	WARN(1, "Unexpected fmrt_find4() result: %d", error);
	return false;
}

verdict handling_hairpinning_mapt(struct xlation *old)
{
	struct xlation *new;
	verdict result;

	log_debug(old, "Step 3: Handling Hairpinning...");

	new = xlation_create(&old->jool);
	if (!new)
		return VERDICT_DROP;
	new->in = old->out;
	new->is_hairpin = true;

	result = translating_the_packet(new);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = sendpkt_send(new);
	if (result != VERDICT_CONTINUE)
		goto end;

	log_debug(old, "Done step 3.");
end:	xlation_destroy(new);
	return result;
}
