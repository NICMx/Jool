#include "nat64/mod/common/core.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/handling_hairpinning.h"
#include "nat64/mod/common/skbuff.h"
#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/common/send_packet.h"

static verdict core_common(struct xlation *state)
{
	verdict result;

	if (xlat_is_nat64()) {
		result = determine_in_tuple(state);
		if (result != VERDICT_CONTINUE)
			return result;
		result = filtering_and_updating(state);
		if (result != VERDICT_CONTINUE)
			return result;
		result = compute_out_tuple(state);
		if (result != VERDICT_CONTINUE)
			return result;
	}
	result = translating_the_packet(state);
	if (result != VERDICT_CONTINUE)
		return result;

	if (is_hairpin(state)) {
		result = handling_hairpinning(state);
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

static void send_icmp4_error(struct xlation *state)
{
	bool success;

	if (state->result.icmp == ICMPERR_NONE)
		return;

	success = icmp64_send4(state->in.skb,
			state->result.icmp,
			state->result.info);
	jstat_inc(state->jool.stats, success
			? JSTAT_ICMP4ERR_SUCCESS
			: JSTAT_ICMP4ERR_FAILURE);
}

verdict core_4to6(struct sk_buff *skb, struct xlator *instance)
{
	struct xlation state;
	verdict result;

	/*
	 * PLEASE REFRAIN FROM READING HEADERS FROM @skb UNTIL
	 * pkt_init_ipv4() HAS pskb_may_pull()ED THEM.
	 */

	xlation_init(&state, instance);

	if (!state.jool.global->cfg.enabled) {
		result = untranslatable(&state, JSTAT_XLATOR_DISABLED);
		goto end;
	}

	log_debug("===============================================");
	log_debug("Jool instance '%s': Received a v4 packet.", instance->iname);

	/* Reminder: This function might change pointers. */
	result = pkt_init_ipv4(&state, skb);
	if (result != VERDICT_CONTINUE)
		goto end;

	/* skb_log(skb, "Incoming IPv4 packet"); */

	result = core_common(&state);
	/* Fall through */

end:
	send_icmp4_error(&state);
	return result;
}

static void send_icmp6_error(struct xlation *state)
{
	bool success;

	if (state->result.icmp == ICMPERR_NONE)
		return;

	success = icmp64_send6(state->in.skb,
			state->result.icmp,
			state->result.info);
	jstat_inc(state->jool.stats, success
			? JSTAT_ICMP6ERR_SUCCESS
			: JSTAT_ICMP6ERR_FAILURE);
}

verdict core_6to4(struct sk_buff *skb, struct xlator *instance)
{
	struct xlation state;
	verdict result;

	/*
	 * PLEASE REFRAIN FROM READING HEADERS FROM @skb UNTIL
	 * pkt_init_ipv6() HAS pskb_may_pull()ED THEM.
	 */

	xlation_init(&state, instance);

	snapshot_record(&state.in.debug.shot1, skb);

	if (!state.jool.global->cfg.enabled) {
		result = untranslatable(&state, JSTAT_XLATOR_DISABLED);
		goto end;
	}

	log_debug("===============================================");
	log_debug("Jool instance '%s': Received a v6 packet.", instance->iname);

	/* Reminder: This function might change pointers. */
	result = pkt_init_ipv6(&state, skb);
	if (result != VERDICT_CONTINUE)
		goto end;

	/* skb_log(skb, "Incoming IPv6 packet"); */
	snapshot_record(&state.in.debug.shot2, skb);

	result = core_common(&state);
	/* Fall through */

end:
	send_icmp6_error(&state);
	return result;
}
