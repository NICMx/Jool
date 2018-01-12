#include "handling-hairpinning.h"

#include "rfc7915/core.h"
#include "send-packet.h"
#include "nat64/compute-outgoing-tuple.h"
#include "nat64/filtering-and-updating.h"
#include "nat64/pool4/db.h"

/**
 * Checks whether @state->out is a hairpin packet.
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
	 * TODO this probably doesn't apply anymore.
	 */
	return pool4db_contains(state->jool.pool4, &state->out.tuple);
}

/**
 * Mirrors the core's behavior by processing @state->out as if it was the
 * incoming packet.
 */
static int handling_hairpinning_nat64(struct xlation *old)
{
	struct xlation new;
	int error;

	log_debug("Step 5: Handling Hairpinning...");

	xlation_init(&new, &old->jool);
	new.jool = old->jool;
	new.in = old->out;

	error = filtering_and_updating(&new);
	if (error)
		goto end;
	error = compute_out_tuple(&new);
	if (error)
		goto end;
	error = translating_the_packet(&new);
	if (error)
		goto end;
	error = sendpkt_send(&new.out);
	if (error)
		goto end;

	log_debug("Done step 5.");
	/* Fall through */

end:
	xlation_put(&new);
	return error;
}

static bool is_hairpin_siit(struct xlation *state)
{
	return pkt_is_intrinsic_hairpin(&state->out);
}

static int handling_hairpinning_siit(struct xlation *old)
{
	struct xlation new;
	int error;

	log_debug("Packet is a hairpin. U-turning...");

	xlation_init(&new, &old->jool);
	new.jool = old->jool;
	new.in = old->out;

	error = translating_the_packet(&new);
	if (error)
		goto end;
	error = sendpkt_send(&new.out);
	if (error)
		goto end;

	log_debug("Done hairpinning.");
	/* Fall through */

end:
	xlation_put(&new);
	return error;
}

bool is_hairpin(struct xlation *state)
{
	switch (XLATOR_TYPE(state)) {
	case XLATOR_SIIT:
		return is_hairpin_siit(state);
	case XLATOR_NAT64:
		return is_hairpin_nat64(state);
	}

	BUG(); /* TODO Hmmmmmmmmmmmmmmmmm. */
	return false;
}

/**
 * Regarding the incoming packet:
 *
 * - If this function succeeds, the incoming packet is left alone.
 *   (Just like everywhere else.)
 * - If this function errors, the incoming packet is freed.
 *   (Just like everywhere else.)
 *
 * Regarding the outgoing packet:
 * - This function frees it regardless of result status.
 *   (So you can think of this function as an alternate sendpkt_send().
 */
int handling_hairpinning(struct xlation *state)
{
	int error;

	switch (XLATOR_TYPE(state)) {
	case XLATOR_SIIT:
		error = handling_hairpinning_siit(state);
		break;
	case XLATOR_NAT64:
		error = handling_hairpinning_nat64(state);
		break;
	default:
		einval(state, JOOL_MIB_UNKNOWN_XLATOR);
		kfree_skb(state->out.skb);
		state->out.skb = NULL;
		return -EINVAL;
	}

	if (error) {
		kfree_skb(state->in.skb);
		state->in.skb = NULL;
	} else {
		dev_kfree_skb(state->out.skb);
		state->out.skb = NULL;
	}

	return error;
}
