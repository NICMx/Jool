#include "mod/common/core.h"

#include "common/config.h"
#include "mod/common/log.h"
#include "mod/common/trace.h"
#include "mod/common/translation_state.h"
#include "mod/common/xlator.h"
#include "mod/common/rfc7915/core.h"
#include "mod/common/steps/compute_outgoing_tuple.h"
#include "mod/common/steps/determine_incoming_tuple.h"
#include "mod/common/steps/filtering_and_updating.h"
#include "mod/common/steps/send_packet.h"

static verdict validate_xlator(struct xlation *state)
{
	struct globals *cfg = &state->jool.globals;

	if (!cfg->enabled)
		return untranslatable(state, JSTAT_XLATOR_DISABLED);
	if (xlation_is_nat64(state) && !cfg->pool6.set) {
		log_warn_once("Cannot translate; pool6 is unset.");
		return untranslatable(state, JSTAT_POOL6_UNSET);
	}

	return VERDICT_CONTINUE;
}

static verdict core_common(struct xlation *state)
{
	verdict result;

	if (xlation_is_nat64(state)) {
		result = determine_in_tuple(state);
		if (result != VERDICT_CONTINUE)
			return result;
		result = filtering_and_updating(state);
		if (result != VERDICT_CONTINUE)
			return result;
		result = compute_out_tuple(state);
		if (result != VERDICT_CONTINUE)
			return result;
	} else {
		result = compute_out_tuple_siit(state);
		if (result != VERDICT_CONTINUE)
			return result;
	}
	result = translating_the_packet(state);
	if (result != VERDICT_CONTINUE)
		return result;

	if (state->jool.is_hairpin(state)) {
		result = state->jool.handling_hairpinning(state);
		kfree_skb(state->out.skb); /* Put this inside of hh()? */
	} else {
		result = sendpkt_send(state);
		/* sendpkt_send() releases out's skb regardless of verdict. */
	}
	if (result != VERDICT_CONTINUE)
		return result;

	log_debug("Success.");
	/*
	 * The new packet was sent, so the original one can die; drop it.
	 *
	 * NF_DROP translates into an error (see nf_hook_slow()).
	 * Sending a replacing & translated version of the packet should not
	 * count as an error, so we free the incoming packet ourselves and
	 * return NF_STOLEN on success.
	 */
	kfree_skb(state->in.skb);
	return stolen(state, JSTAT_SUCCESS);
}

static void send_icmp4_error(struct xlation *state, verdict result)
{
	bool success;

	if (state->result.icmp == ICMPERR_NONE)
		return;
	if (result == VERDICT_UNTRANSLATABLE)
		return; /* Linux will decide what to do. */

	success = icmp64_send4(state->in.skb,
			state->result.icmp,
			state->result.info);
	jstat_inc(state->jool.stats, success
			? JSTAT_ICMP4ERR_SUCCESS
			: JSTAT_ICMP4ERR_FAILURE);
}

verdict core_4to6(struct sk_buff *skb, struct xlation *state)
{
	verdict result;

	jstat_inc(state->jool.stats, JSTAT_RECEIVED4);

	/*
	 * PLEASE REFRAIN FROM READING HEADERS FROM @skb UNTIL
	 * pkt_init_ipv4() HAS pskb_may_pull()ED THEM.
	 */

	result = validate_xlator(state);
	if (result != VERDICT_CONTINUE)
		goto end;

	log_debug("===============================================");
	log_debug("Jool instance '%s': Received a v4 packet.",
			state->jool.iname);

	/* Reminder: This function might change pointers. */
	result = pkt_init_ipv4(state, skb);
	if (result != VERDICT_CONTINUE)
		goto end;

	if (state->jool.globals.trace)
		pkt_trace4(state);
	/* skb_log(skb, "Incoming IPv4 packet"); */

	result = core_common(state);
	/* Fall through */

end:
	send_icmp4_error(state, result);
	return result;
}

static void send_icmp6_error(struct xlation *state, verdict result)
{
	bool success;

	if (state->result.icmp == ICMPERR_NONE)
		return;
	if (result == VERDICT_UNTRANSLATABLE)
		return; /* Linux will decide what to do. */

	success = icmp64_send6(state->in.skb,
			state->result.icmp,
			state->result.info);
	jstat_inc(state->jool.stats, success
			? JSTAT_ICMP6ERR_SUCCESS
			: JSTAT_ICMP6ERR_FAILURE);
}

verdict core_6to4(struct sk_buff *skb, struct xlation *state)
{
	verdict result;

	jstat_inc(state->jool.stats, JSTAT_RECEIVED6);

	/*
	 * PLEASE REFRAIN FROM READING HEADERS FROM @skb UNTIL
	 * pkt_init_ipv6() HAS pskb_may_pull()ED THEM.
	 */

	snapshot_record(&state->in.debug.shot1, skb);

	result = validate_xlator(state);
	if (result != VERDICT_CONTINUE)
		goto end;

	log_debug("===============================================");
	log_debug("Jool instance '%s': Received a v6 packet.",
			state->jool.iname);

	/* Reminder: This function might change pointers. */
	result = pkt_init_ipv6(state, skb);
	if (result != VERDICT_CONTINUE)
		goto end;

	if (state->jool.globals.trace)
		pkt_trace6(state);
	/* skb_log(skb, "Incoming IPv6 packet"); */
	snapshot_record(&state->in.debug.shot2, skb);

	result = core_common(state);
	/* Fall through */

end:
	send_icmp6_error(state, result);
	return result;
}
