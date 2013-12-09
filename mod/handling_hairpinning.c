#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/send_packet.h"


/**
 * Checks whether "pkt" is a hairpin packet.
 *
 * @param pkt outgoing packet the NAT64 would send if it's not a hairpin.
 * @return whether pkt is a hairpin packet.
 */
bool is_hairpin(struct packet *pkt)
{
	struct in_addr addr;

	if (pkt_get_l3proto(pkt) != L3PROTO_IPV4)
		return false;

	pkt_get_ipv4_dst_addr(pkt, &addr);
	return pool4_contains(&addr);
}

/**
 * Mirrors the core's behavior by processing pkt_in as if it was the incoming packet.
 *
 * @param pkt_in the outgoing packet. Except because it's a hairpin, here it's treated as if it was
 *		the one received from the network.
 * @param tuple_in pkt_in's tuple.
 * @return whether we managed to U-turn the packet successfully.
 */
verdict handling_hairpinning(struct packet *pkt_in, struct tuple *tuple_in)
{
	struct packet *pkt_out = NULL;
	struct tuple tuple_out;

	log_debug("Step 5: Handling Hairpinning...");

	if (pkt_get_l4proto(pkt_in) == L4PROTO_ICMP) {
		/* RFC 6146 section 2 (Definition of "Hairpinning"). */
		log_warning("ICMP is NOT supported by hairpinning. Dropping packet...");
		goto fail;
	}

	if (filtering_and_updating(pkt_in->first_fragment, tuple_in) != VER_CONTINUE)
		goto fail;
	if (compute_out_tuple(tuple_in, &tuple_out) != VER_CONTINUE)
		goto fail;
	if (translating_the_packet(&tuple_out, pkt_in, &pkt_out) != VER_CONTINUE)
		goto fail;
	if (send_pkt(pkt_out) != VER_CONTINUE)
		goto fail;

	pkt_kfree(pkt_out);
	log_debug("Done step 5.");
	return VER_CONTINUE;

fail:
	pkt_kfree(pkt_out);
	return VER_DROP;
}
