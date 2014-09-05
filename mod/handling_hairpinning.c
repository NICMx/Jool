#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/stats.h"


/**
 * Checks whether "pkt" is a hairpin packet.
 *
 * @param pkt outgoing packet the NAT64 would send if it's not a hairpin.
 * @return whether pkt is a hairpin packet.
 */
bool is_hairpin(struct sk_buff *skb)
{
	struct in_addr addr;

	if (skb_l3_proto(skb) != L3PROTO_IPV4)
		return false;

	addr.s_addr = ip_hdr(skb)->daddr;
	return pool4_contains(&addr);
}

/**
 * Mirrors the core's behavior by processing skb_in as if it was the incoming packet.
 *
 * @param skb_in the outgoing packet. Except because it's a hairpin, here it's treated as if it was
 *		the one received from the network.
 * @param tuple_in skb_in's tuple.
 * @return whether we managed to U-turn the packet successfully.
 */
verdict handling_hairpinning(struct sk_buff *skb_in, struct tuple *tuple_in)
{
	struct sk_buff *skb_out;
	struct tuple tuple_out;
	verdict result;
	int field = 0;

	log_debug("Step 5: Handling Hairpinning...");

	if (skb_l4_proto(skb_in) == L4PROTO_ICMP) {
		/* RFC 6146 section 2 (Definition of "Hairpinning"). */
		log_debug("ICMP is not supported by hairpinning. Dropping packet...");
		return VER_DROP;
	}

	result = filtering_and_updating(skb_in, tuple_in);
	if (result != VER_CONTINUE)
		return result;
	result = compute_out_tuple(tuple_in, &tuple_out, &field);
	if (result != VER_CONTINUE) {
		inc_stats(skb_in, field);
		return result;
	}
	result = translating_the_packet(&tuple_out, skb_in, &skb_out);
	if (result != VER_CONTINUE)
		return result;
	result = send_pkt(skb_out);
	if (result != VER_CONTINUE)
		return result;

	log_debug("Done step 5.");
	return VER_CONTINUE;
}
