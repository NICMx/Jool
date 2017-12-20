#include "handling-hairpinning.h"

#include "rfc7915/core.h"
#include "send-packet.h"
#include "nat64/compute-outgoing-tuple.h"
#include "nat64/filtering-and-updating.h"
#include "nat64/pool4/db.h"

/**
 * Checks whether "pkt" is a hairpin packet.
 *
 * @param pkt outgoing packet the NAT64 would send if it's not a hairpin.
 * @return whether pkt is a hairpin packet.
 */
static bool is_hairpin_nat64(struct xlation *state)
{
	if (state->out.tuple.l3_proto == L3PROTO_IPV6)
		return false;

	/*
	 * This collides with RFC 6146.
	 * The RFC says "packet (...) destination address", but I'm using
	 * "tuple destination address".
	 * I mean you can throw tomatoes, but this makes lot more sense to me.
	 * Otherwise Jool would hairpin ICMP errors that were actually intended
	 * for its node. It might take a miracle for these packets to exist,
	 * but hey, why the hell not.
	 */
	return pool4db_contains(state->jool.nat64.pool4, &state->out);
}

/**
 * Mirrors the core's behavior by processing skb_in as if it was the incoming packet.
 *
 * @param skb_in the outgoing packet. Except because it's a hairpin, here it's treated as if it was
 *		the one received from the network.
 * @param tuple_in skb_in's tuple.
 * @return whether we managed to U-turn the packet successfully.
 */
static verdict handling_hairpinning_nat64(struct xlation *old)
{
	struct xlation new;
	verdict result;

	log_debug("Step 5: Handling Hairpinning...");

	xlation_init(&new, &old->jool);
	new.jool = old->jool;
	new.in = old->out;

	result = filtering_and_updating(&new);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = compute_out_tuple(&new);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = translating_the_packet(&new);
	if (result != VERDICT_CONTINUE)
		goto end;
	result = sendpkt_send(&new);
	if (result != VERDICT_CONTINUE)
		goto end;

	log_debug("Done step 5.");

end:
	xlation_put(&new);
	return VERDICT_CONTINUE;
}

static bool is_hairpin_siit(struct xlation *state)
{
	return pkt_is_intrinsic_hairpin(&state->out);
}

static verdict handling_hairpinning_siit(struct xlation *old)
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

bool is_hairpin(struct xlation *state)
{
	switch (state->jool.type) {
	case XLATOR_SIIT:
		return is_hairpin_siit(state);
	case XLATOR_NAT64:
		return is_hairpin_nat64(state);
	}

	BUG();
	return false;
}

verdict handling_hairpinning(struct xlation *state)
{
	switch (state->jool.type) {
	case XLATOR_SIIT:
		return handling_hairpinning_siit(state);
	case XLATOR_NAT64:
		return handling_hairpinning_nat64(state);
	}

	BUG();
	return VERDICT_DROP;
}
