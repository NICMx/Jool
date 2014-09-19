#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/session_db.h"

verdict compute_out_tuple(struct tuple *in, struct tuple *out, int *field)
{
	struct session_entry *session;
	int error;

	log_debug("Step 3: Computing the Outgoing Tuple");

	error = sessiondb_get(in, &session);
	if (error) {
		/*
		 * Bogus ICMP errors might cause this because Filtering never cares for them,
		 * so it's not critical.
		 */
		log_debug("Error code %d while trying to find the packet's session entry.", error);
		*field = IPSTATS_MIB_INNOROUTES;
		return VER_DROP;
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
		out->src.addr.ipv4 = session->ipv4.local.address;
		out->src.l4_id = session->ipv4.local.l4_id;
		out->dst.addr.ipv4 = session->ipv4.remote.address;
		out->dst.l4_id = session->ipv4.remote.l4_id;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = in->l4_proto;
		out->src.addr.ipv6 = session->ipv6.local.address;
		out->src.l4_id = session->ipv6.local.l4_id;
		out->dst.addr.ipv6 = session->ipv6.remote.address;
		out->dst.l4_id = session->ipv6.remote.l4_id;
		break;
	}

	session_return(session);
	log_tuple(out);

	log_debug("Done step 3.");
	return VER_CONTINUE;
}
