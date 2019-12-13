#include "mod/common/rfc7915/core.h"

#include "mod/common/log.h"
#include "mod/common/rfc7915/common.h"

static bool has_l4_hdr(struct xlation *state)
{
	switch (pkt_l3_proto(&state->in)) {
	case L3PROTO_IPV6:
		return is_first_frag6(pkt_frag_hdr(&state->in));
	case L3PROTO_IPV4:
		return is_first_frag4(pkt_ip4_hdr(&state->in));
	}

	WARN(1, "Supposedly unreachable code reached. Proto: %u",
			pkt_l3_proto(&state->in));
	return false;
}

verdict translating_the_packet(struct xlation *state)
{
	/*
	 * Here's the thing:
	 *
	 * In order to allocate the outgoing packet we need its length.
	 * In order to find its length we need the MTU of the outgoing
	 * interface (because fragmentation).
	 * In order to find the MTU of the outgoing interface, we need the
	 * outgoing interface.
	 * In order to find the outgoing interface, we need to route the
	 * outgoing packet.
	 * To route the outgoing packet (assuming it hasn't been already
	 * routed), we need flowi fields (set A).
	 * Among the flowi fields (set A), there are several outgoing packet
	 * header fields. The IP addresses are among them.
	 * To get the source address, we might need to route the outgoing
	 * packet (without source address) (because RFC 6791).
	 * To route the outgoing packet (without source address), we need flowi
	 * fields (set B).
	 * Among the flowi fields (set B), we need to include the destination
	 * address, ports and some other header fields.
	 *
	 * And there's a catch: If the packet is a PTB or FN, the transport
	 * header will need the MTU of the outgoing interface.
	 *
	 * Therefore, the order is
	 *
	 * If packet is ICMP error and 6791 pool is in host mode,
	 *	1. Outer IP and Transport Headers, except Source Address and MTU
	 *	2. Route
	 *	3. Source address and MTU
	 * else,
	 *	1. Outer IP and Transport Headers, except MTU
	 *	2. Route
	 *	3. MTU
	 * 4. Packet allocation
	 *
	 * Therefore, we need to translate the headers before actually
	 * allocating the outgoing packet.
	 */

	struct translation_steps *steps = ttpcomm_get_steps(&state->in);
	verdict result;

	if (xlation_is_nat64(state))
		log_debug("Step 4: Translating the Packet");
	else
		log_debug("Translating the Packet.");

	result = steps->skb_alloc_fn(state);
	if (result != VERDICT_CONTINUE)
		return result;

	result = steps->l3_hdr_fn(state);
	if (result != VERDICT_CONTINUE)
		goto revert;

	if (has_l4_hdr(state)) {
		result = steps->l4_hdr_fn(state);
		if (result != VERDICT_CONTINUE)
			goto revert;
	}

	if (xlation_is_nat64(state))
		log_debug("Done step 4.");
	return VERDICT_CONTINUE;

revert:
	kfree_skb_list(state->out.skb);
	return result;
}
