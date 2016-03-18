#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/mod/stateful/session/db.h"

static struct session_entry *find_session(struct xlation *state)
{
	struct session_entry *session;
	int error;

	if (state->session) {
		session_get(state->session);
		return state->session;
	}

	error = sessiondb_find(state->jool.nat64.session, &state->in.tuple,
			NULL, NULL, &session);
	if (error) {
		/*
		 * Bogus ICMP errors might cause this because Filtering skips
		 * them, so it's not critical.
		 */
		log_debug("Session not found. Error code is %d.", error);
		return NULL;
	}

	return session;
}

verdict compute_out_tuple(struct xlation *state)
{
	struct session_entry *session;
	struct tuple *in;
	struct tuple *out;

	log_debug("Step 3: Computing the Outgoing Tuple");

	session = find_session(state);
	if (!session)
		return VERDICT_ACCEPT;

	/*
	 * Though the end result is the same, the following section of code
	 * collides with the RFC in a superfluous sense.
	 *
	 * If the IPv6 pool has multiple prefixes, algorithmically generating
	 * addresses at this point is pointless because, in order to do that,
	 * we'd need to know which prefix was used when the session was created.
	 * This bit of information would have to be extracted from the session.
	 * However, the address already algorithmically generated also belongs
	 * to the session. So why bother generating it again? Just copy it.
	 *
	 * Additionally, the RFC wants some information extracted from the BIB
	 * entry. We *also* extract that information from the session because
	 * it's the same, by definition.
	 *
	 * And finally, the RFC wants some information extracted from the tuple.
	 * Same deal. If you draw all the scenarios (weirdass ICMP errors
	 * included), it's always the same as the session.
	 *
	 * Given all of that, I really don't understand why the RFC bothers with
	 * any of this, including making a distinction between 3-tuples and
	 * 5-tuples. The outgoing tuple is always a copy of the other side of
	 * the session, plain and simple. When you think about it, that last
	 * claim makes sense even in a general sense.
	 */

	in = &state->in.tuple;
	out = &state->out.tuple;

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = in->l4_proto;
		out->src.addr4 = session->src4;
		out->dst.addr4 = session->dst4;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = in->l4_proto;
		out->src.addr6 = session->dst6;
		out->dst.addr6 = session->src6;
		break;
	}

	session_put(session, false);
	log_tuple(out);

	log_debug("Done step 3.");
	return VERDICT_CONTINUE;
}
