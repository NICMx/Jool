#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/bib.h"


/**
 * Section 3.6.1 of RFC 6146.
 */
static verdict tuple5(struct tuple *in, struct tuple *out)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;
	int error;

	if (!pool6_peek(&prefix)) {
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty. Cannot translate.");
		return VER_DROP;
	}

	spin_lock_bh(&bib_session_lock);
	error = bib_get(in, &bib);
	if (error) {
		log_warning("Error code %d while trying to find a BIB entry we just created or updated in "
				"the Filtering and Updating step...", error);
		goto lock_fail;
	}

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = in->l4_proto;
		out->src.addr.ipv4 = bib->ipv4.address;
		out->src.l4_id = bib->ipv4.l4_id;
		if (is_error(addr_6to4(&in->dst.addr.ipv6, &prefix, &out->dst.addr.ipv4)))
			goto lock_fail;
		out->dst.l4_id = in->dst.l4_id;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = in->l4_proto;
		if (is_error(addr_4to6(&in->src.addr.ipv4, &prefix, &out->src.addr.ipv6)))
			goto lock_fail;
		out->src.l4_id = in->src.l4_id;
		out->dst.addr.ipv6 = bib->ipv6.address;
		out->dst.l4_id = bib->ipv6.l4_id;
		break;
	}

	spin_unlock_bh(&bib_session_lock);
	log_tuple(out);
	return VER_CONTINUE;

lock_fail:
	spin_unlock_bh(&bib_session_lock);
	return VER_DROP;
}

/**
 * Section 3.6.2 of RFC 6146.
 */
static verdict tuple3(struct tuple *in, struct tuple *out)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;
	int error;

	if (!pool6_peek(&prefix)) {
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty. Cannot translate.");
		return VER_DROP;
	}

	spin_lock_bh(&bib_session_lock);
	error = bib_get(in, &bib);
	if (error) {
		log_warning("Error code %d while trying to find a BIB entry we just created or updated in "
				"the Filtering and Updating step...", error);
		goto lock_fail;
	}

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = L4PROTO_ICMP;
		out->src.addr.ipv4 = bib->ipv4.address;
		if (is_error(addr_6to4(&in->dst.addr.ipv6, &prefix, &out->dst.addr.ipv4)))
			goto lock_fail;
		out->icmp_id = bib->ipv4.l4_id;
		out->dst.l4_id = out->icmp_id;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = L4PROTO_ICMP;
		if (is_error(addr_4to6(&in->src.addr.ipv4, &prefix, &out->src.addr.ipv6)))
			goto lock_fail;
		out->dst.addr.ipv6 = bib->ipv6.address;
		out->icmp_id = bib->ipv6.l4_id;
		out->dst.l4_id = out->icmp_id;
		break;
	}

	spin_unlock_bh(&bib_session_lock);
	log_tuple(out);
	return VER_CONTINUE;

lock_fail:
	spin_unlock_bh(&bib_session_lock);
	return VER_DROP;
}

/**
 * Section 3.6 of RFC 6146.
 */
verdict compute_out_tuple(struct tuple *in, struct tuple *out)
{
	verdict result;
	log_debug("Step 3: Computing the Outgoing Tuple");

	result = is_5_tuple(in) ? tuple5(in, out) : tuple3(in, out);

	log_debug("Done step 3.");
	return result;
}
