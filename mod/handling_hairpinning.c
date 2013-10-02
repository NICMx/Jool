#include "nat64/mod/handling_hairpinning.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/packet_db.h"


bool is_hairpin(struct tuple *outgoing)
{
	return (outgoing->l3_proto == L3PROTO_IPV4) && pool4_contains(&outgoing->dst.addr.ipv4);
}

bool handling_hairpinning(struct paket *pkt_in, struct tuple *tuple_in)
{
	struct packet *pkt_out;
	struct tuple tuple_out;

	log_debug("Step 5: Handling Hairpinning...");

	if (tuple_in->l4_proto == L4PROTO_ICMP) {
		/* RFC 6146 section 2 (Definition of "Hairpinning"). */
		log_warning("ICMP is NOT supported by hairpinning. Dropping packet...");
		goto free_and_fail;
	}

	if (filtering_and_updating(pkt_in, tuple_in) != NF_ACCEPT)
		goto free_and_fail;
	if (!compute_out_tuple_4to6(tuple_in, pkt_in, &tuple_out))
		goto free_and_fail;
	if (!translating_the_packet_4to6(&tuple_out, pkt_in, &pkt_out))
		goto free_and_fail;
	if (!send_packet_ipv6(pkt_in, pkt_out))
		goto fail;

	log_debug("Done step 5.");
	return true;

free_and_fail:
	pkt_kfree(pkt_out, true);
	/* Fall through. */

fail:
	return false;
}
