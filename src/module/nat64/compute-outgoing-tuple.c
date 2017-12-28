#include "nat64/compute-outgoing-tuple.h"

#include "rfc6052.h"
#include "nat64/bib/db.h"

/**
 * Ensures @state->entries->bib is computed and valid.
 * (Assuming @state really maps to a databased session, that is.)
 */
static int find_bib(struct xlation *state)
{
	int error;

	if (state->entries.bib_set)
		return 0;

	error = bib_find(state->jool.bib, &state->in.tuple, &state->entries);
	switch (error) {
	case 0:
		return 0;
	case -ESRCH:
		/*
		 * Bogus ICMP errors might cause this because Filtering skips
		 * them, so it's by no means critical.
		 */
		log_debug("Session not found.");
		return breakdown(state, JOOL_MIB_ICMP_ERROR_NO_BIB, error);
	} /* EINVAL can fall through. */

	log_debug("bib_find() spew unexpected error code %d.", error);
	return breakdown(state, JOOL_MIB_UNKNOWN, error);
}

static int xlat_addr64(struct xlation *state, struct ipv4_transport_addr *addr4)
{
	/* The RFC labels this as "(D', d)". */
	struct ipv6_transport_addr *d = &state->in.tuple.dst.addr6;

	addr4->l4 = d->l4;
	return rfc6052_6to4(state, &d->l3, &addr4->l3);
}

static int xlat_addr46(struct xlation *state, struct ipv6_transport_addr *addr6)
{
	/* The RFC labels this as (S, s). */
	struct ipv4_transport_addr *s = &state->in.tuple.src.addr4;

	addr6->l4 = s->l4;
	return rfc6052_4to6(state, &s->l3, &addr6->l3);
}

int compute_out_tuple(struct xlation *state)
{
	struct tuple *in;
	struct tuple *out;
	int error;

	log_debug("Step 3: Computing the Outgoing Tuple");

	error = find_bib(state);
	if (error)
		return error;

	in = &state->in.tuple;
	out = &state->out.tuple;

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = in->l4_proto;
		out->src.addr4 = state->entries.session.src4;
		error = xlat_addr64(state, &out->dst.addr4);
		if (error)
			return error;
		if (is_3_tuple(out))
			out->dst.addr4.l4 = out->src.addr4.l4;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = in->l4_proto;
		error = xlat_addr46(state, &out->src.addr6);
		if (error)
			return error;
		out->dst.addr6 = state->entries.session.src6;
		if (is_3_tuple(out))
			out->src.addr6.l4 = out->dst.addr6.l4;
		break;
	}

	log_tuple(out);
	log_debug("Done step 3.");
	return 0;
}
