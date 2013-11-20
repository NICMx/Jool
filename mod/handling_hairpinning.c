#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/send_packet.h"


bool is_hairpin(struct tuple *outgoing)
{
	return (outgoing->l3_proto == L3PROTO_IPV4) && pool4_contains(&outgoing->dst.addr.ipv4);
}

verdict handling_hairpinning(struct packet *pkt_in, struct tuple *tuple_in)
{
	struct packet pkt_out;
	struct tuple tuple_out;

	log_debug("Step 5: Handling Hairpinning...");

	if (pkt_get_l4proto(pkt_in) == L4PROTO_ICMP) {
		/* RFC 6146 section 2 (Definition of "Hairpinning"). */
		log_warning("ICMP is NOT supported by hairpinning. Dropping packet...");
		goto fail;
	}

	if (filtering_and_updating(pkt_in, tuple_in) != VER_CONTINUE)
		goto fail;
	if (compute_out_tuple(tuple_in, pkt_in, &tuple_out) != VER_CONTINUE)
		goto fail;
	if (translating_the_packet(&tuple_out, pkt_in, &pkt_out) != VER_CONTINUE)
		goto free_and_fail;
	if (send_pkt(&pkt_out) != VER_CONTINUE)
		goto free_and_fail;

	pkt_kfree(&pkt_out, false);
	log_debug("Done step 5.");
	return VER_CONTINUE;

free_and_fail:
	pkt_kfree(&pkt_out, false);
	/* Fall through. */

fail:
	return VER_DROP;
}
