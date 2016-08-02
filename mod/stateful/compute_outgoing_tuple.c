#include "nat64/mod/stateful/compute_outgoing_tuple.h"

#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/stateful/bib/db.h"

/**
 * Ensures @state->entries->bib is computed and valid.
 * (Assuming @state really maps to a databased session, that is.)
 */
static int find_bib(struct xlation *state)
{
	int error;

	if (state->entries.bib_set)
		return 0;

	error = bib_find(state->jool.nat64.bib, &state->in.tuple,
			&state->entries);
	if (error) {
		/*
		 * Bogus ICMP errors might cause this because Filtering skips
		 * them, so it's not critical.
		 */
		log_debug("Session not found. Error code is %d.", error);
	}

	return error;
}

static int xlat_addr64(struct xlation *state, struct ipv4_transport_addr *addr4)
{
	/* The RFC labels this as "(D', d)". */
	struct ipv6_transport_addr *d = &state->in.tuple.dst.addr6;

	addr4->l4 = d->l4;
	return rfc6052_6to4(state->jool.pool6, &d->l3, &addr4->l3);
}

static int xlat_addr46(struct xlation *state, struct ipv6_transport_addr *addr6)
{
	/* The RFC labels this as (S, s). */
	struct ipv4_transport_addr *s = &state->in.tuple.src.addr4;

	addr6->l4 = s->l4;
	return rfc6052_4to6(state->jool.pool6, &s->l3, &addr6->l3);
}

verdict compute_out_tuple(struct xlation *state)
{
	struct tuple *in;
	struct tuple *out;

	log_debug("Step 3: Computing the Outgoing Tuple");

	if (find_bib(state))
		return VERDICT_ACCEPT;

	in = &state->in.tuple;
	out = &state->out.tuple;

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = in->l4_proto;
		out->src.addr4 = state->entries.session.src4;
		if (xlat_addr64(state, &out->dst.addr4))
			return VERDICT_ACCEPT;

		if (is_3_tuple(out))
			out->dst.addr4.l4 = out->src.addr4.l4;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = in->l4_proto;
		if (xlat_addr46(state, &out->src.addr6))
			return VERDICT_ACCEPT;
		out->dst.addr6 = state->entries.session.src6;

		if (is_3_tuple(out))
			out->src.addr6.l4 = out->dst.addr6.l4;
		break;
	}

	log_tuple(out);
	log_debug("Done step 3.");
	return VERDICT_CONTINUE;
}
