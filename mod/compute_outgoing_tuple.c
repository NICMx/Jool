#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/bib.h"


static verdict tuple5(struct tuple *in, struct tuple *out)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;

	if (!pool6_peek(&prefix)) {
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty. Cannot translate.");
		return VER_DROP;
	}

	spin_lock_bh(&bib_session_lock);
	bib = bib_get(in);
	if (!bib) {
		log_crit(ERR_MISSING_BIB, "Could not find the BIB entry we just created/updated!");
		goto lock_fail;
	}

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = in->l4_proto;
		out->src.addr.ipv4 = bib->ipv4.address;
		out->src.l4_id = bib->ipv4.l4_id;
		if (!addr_6to4(&in->dst.addr.ipv6, &prefix, &out->dst.addr.ipv4))
			goto lock_fail;
		out->dst.l4_id = in->dst.l4_id;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = in->l4_proto;
		if (!addr_4to6(&in->src.addr.ipv4, &prefix, &out->src.addr.ipv6))
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

static verdict tuple3(struct tuple *in, struct tuple *out)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;

	if (!pool6_peek(&prefix)) {
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty. Cannot translate.");
		return VER_DROP;
	}

	spin_lock_bh(&bib_session_lock);
	bib = bib_get(in);
	if (!bib) {
		log_crit(ERR_MISSING_BIB, "Could not find the BIB entry we just created/updated!");
		goto lock_fail;
	}

	switch (in->l3_proto) {
	case L3PROTO_IPV6:
		out->l3_proto = L3PROTO_IPV4;
		out->l4_proto = L4PROTO_ICMP;
		out->src.addr.ipv4 = bib->ipv4.address;
		if (!addr_6to4(&in->dst.addr.ipv6, &prefix, &out->dst.addr.ipv4))
			goto lock_fail;
		out->icmp_id = bib->ipv4.l4_id;
		out->dst.l4_id = out->icmp_id;
		break;

	case L3PROTO_IPV4:
		out->l3_proto = L3PROTO_IPV6;
		out->l4_proto = L4PROTO_ICMP;
		if (!addr_4to6(&in->src.addr.ipv4, &prefix, &out->src.addr.ipv6))
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

verdict compute_out_tuple(struct tuple *in, struct packet *pkt_in, struct tuple *out)
{
	struct icmp6hdr *icmp6;
	struct icmphdr *icmp4;
	verdict result = VER_DROP;

	log_debug("Step 3: Computing the Outgoing Tuple");

	switch (pkt_get_l4proto(pkt_in)) {
	case L4PROTO_TCP:
	case L4PROTO_UDP:
		result = tuple5(in, out);
		break;

	case L4PROTO_ICMP:
		switch (pkt_get_l3proto(pkt_in)) {
		case L3PROTO_IPV6:
			icmp6 = frag_get_icmp6_hdr(pkt_in->first_fragment);
			result = is_icmp6_info(icmp6->icmp6_type)
					? tuple3(in, out)
					: tuple5(in, out);
			break;

		case L3PROTO_IPV4:
			icmp4 = frag_get_icmp4_hdr(pkt_in->first_fragment);
			result = is_icmp4_info(icmp4->type)
					? tuple3(in, out)
					: tuple5(in, out);
			break;
		}
		break;

	default:
		log_crit(ERR_L4PROTO, "Unsupported transport protocol: %u.", pkt_get_l4proto(pkt_in));
		result = VER_DROP;
	}

	log_debug("Done step 3.");
	return result;
}
