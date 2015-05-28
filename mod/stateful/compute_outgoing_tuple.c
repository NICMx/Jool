#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateful/session/db.h"

verdict compute_out_tuple(struct tuple *in, struct tuple *out, struct packet *pkt_in)
{
	struct session_entry *session;
	int error;

	log_debug("Step 3: Computing the Outgoing Tuple");

	error = sessiondb_get(in, NULL, NULL, &session);
	if (error) {
		/*
		 * Bogus ICMP errors might cause this because Filtering never cares for them,
		 * so it's not critical.
		 */
		log_debug("Error code %d while trying to find the packet's session entry.", error);
		inc_stats(pkt_in, IPSTATS_MIB_INNOROUTES);
		return VERDICT_DROP;
	}

	/*
	 * Though the end result is the same, the following section of code collides with the RFC
	 * in a superfluous sense.
	 *
	 * If the IPv6 pool has multiple prefixes, algorithmically generating addresses at this point
	 * is pointless because, in order to do that, we'd need to know which prefix was used when the
	 * session was created. This bit of information would have to be extracted from the session.
	 * However, the address already algorithmically generated also belongs to the session.
	 * So why bother generating it again? Just copy it.
	 *
	 * Additionally, the RFC wants some information extracted from the BIB entry.
	 * We *also* extract that information from the session because it's the same, by definition.
	 *
	 * And finally, the RFC wants some information extracted from the tuple.
	 * Same deal. If you draw all the scenarios (weirdass ICMP errors included), it's always the
	 * same as the session.
	 *
	 * Given all of that, I really don't understand why the RFC bothers with any of this, including
	 * making a distinction between 3-tuples and 5-tuples. The outgoing tuple is always a copy of
	 * the other side of the session, plain and simple. When you think about it, that last claim
	 * makes sense even in a general sense.
	 */

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = in->l4_proto;
		out->src.addr4 = session->local4;
		out->dst.addr4 = session->remote4;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = in->l4_proto;
		out->src.addr6 = session->local6;
		out->dst.addr6 = session->remote6;
		break;
	}

	session_return(session);
	log_tuple(out);

	log_debug("Done step 3.");
	return VERDICT_CONTINUE;
}
