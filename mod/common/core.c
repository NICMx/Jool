#include "nat64/mod/common/core.h"

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/handling_hairpinning.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/timestamp.h"
#include "nat64/mod/common/translation_state.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/determine_incoming_tuple.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/common/send_packet.h"

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>

#define EXECUTE(action, tst) ({\
		TIMESTAMP_START(timer); \
		result = action; \
		TIMESTAMP_STOP(timer, tst, result == VERDICT_CONTINUE); \
		result; \
	})


static verdict core_common(struct xlation *state, bool *success)
{
	verdict result;
	TIMESTAMP_DECLARE(timer);

	if (xlat_is_nat64()) {
		result = EXECUTE(determine_in_tuple(state), TST_DIT);
		if (result != VERDICT_CONTINUE)
			goto end;
		result = EXECUTE(filtering_and_updating(state), TST_FAU);
		if (result != VERDICT_CONTINUE)
			goto end;
		result = EXECUTE(compute_out_tuple(state), TST_COT);
		if (result != VERDICT_CONTINUE)
			goto end;
	}

	result = EXECUTE(translating_the_packet(state), TST_TTP);
	if (result != VERDICT_CONTINUE)
		goto end;

	if (is_hairpin(state)) {
		result = EXECUTE(handling_hairpinning(state), TST_HH);
		kfree_skb(state->out.skb); /* Put this inside of hh()? */
	} else {
		result = EXECUTE(sendpkt_send(state), TST_SP);
		/* sendpkt_send() releases out's skb regardless of verdict. */
	}

	if (result != VERDICT_CONTINUE)
		goto end;

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
	result = VERDICT_STOLEN;
	*success = true;
	/* Fall through. */

end:
	if (result == VERDICT_ACCEPT)
		log_debug("Returning the packet to the kernel.");
	return result;
}

static int init_pkt4(struct packet *pkt, struct sk_buff *skb)
{
	int error;
	TIMESTAMP_DECLARE_START(timer);

	error = pkt_init_ipv4(pkt, skb);

	TIMESTAMP_STOP(timer, TST_PKT4_INIT, !error);
	return error;
}

unsigned int core_4to6(struct sk_buff *skb, const struct net_device *dev)
{
	struct xlation state;
	struct iphdr *hdr = ip_hdr(skb);
	bool success = false;
	verdict result;
	TIMESTAMP_DECLARE_START(timer);

	xlation_init(&state);

	if (xlator_find(dev_net(dev), &state.jool))
		return NF_ACCEPT;
	if (!state.jool.global->cfg.enabled) {
		xlation_put(&state);
		return NF_ACCEPT;
	}

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	/* Reminder: This function might change pointers. */
	if (init_pkt4(&state.in, skb)) {
		xlation_put(&state);
		return NF_DROP;
	}

	result = core_common(&state, &success);

	xlation_put(&state);
	TIMESTAMP_STOP(timer, TST46_FULL_TRANSLATION, success);
	return result;
}

static int init_pkt6(struct packet *pkt, struct sk_buff *skb)
{
	int error;
	TIMESTAMP_DECLARE_START(timer);

	error = pkt_init_ipv6(pkt, skb);

	TIMESTAMP_STOP(timer, TST_PKT6_INIT, !error);
	return error;
}

unsigned int core_6to4(struct sk_buff *skb, const struct net_device *dev)
{
	struct xlation state;
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	bool success = false;
	verdict result;
	TIMESTAMP_DECLARE_START(timer);

	xlation_init(&state);

	snapshot_record(&state.in.debug.shot1, skb);

	if (xlator_find(dev_net(dev), &state.jool))
		return NF_ACCEPT;
	if (!state.jool.global->cfg.enabled) {
		xlation_put(&state);
		return NF_ACCEPT;
	}

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &hdr->saddr,
			&hdr->daddr);

	/* Reminder: This function might change pointers. */
	if (init_pkt6(&state.in, skb)) {
		xlation_put(&state);
		return NF_DROP;
	}

	snapshot_record(&state.in.debug.shot2, skb);

	if (xlat_is_nat64()) {
		result = fragdb_handle(state.jool.nat64.frag, &state.in);
		if (result != VERDICT_CONTINUE) {
			xlation_put(&state);
			return result;
		}
	}

	result = core_common(&state, &success);

	xlation_put(&state);
	TIMESTAMP_STOP(timer, TST64_FULL_TRANSLATION, success);
	return result;
}
