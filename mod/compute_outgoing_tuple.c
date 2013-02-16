#include "nat64/compute_outgoing_tuple.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "nat64/rfc6052.h"
#include "nat64/pool6.h"
#include "nat64/bib.h"


static bool switch_l4_proto(u_int8_t proto_in, u_int8_t *proto_out)
{
	switch (proto_in) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		*proto_out = proto_in;
		return true;
	case IPPROTO_ICMP:
		*proto_out = IPPROTO_ICMPV6;
		return true;
	case IPPROTO_ICMPV6:
		*proto_out = IPPROTO_ICMP;
		return true;
	default:
		log_crit(ERR_L4PROTO, "Unknown l4 protocol: %u.", proto_in);
		return false;
	}
}

static bool tuple5(struct nf_conntrack_tuple *in, struct nf_conntrack_tuple *out,
		enum translation_mode mode)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;

	log_debug("Step 3: Computing the Outgoing Tuple");

	if (!pool6_peek(&prefix)) {
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty. Cannot translate.");
		return false;
	}

	spin_lock_bh(&bib_session_lock);
	bib = bib_get(in);
	if (!bib) {
		log_crit(ERR_MISSING_BIB, "Could not find the BIB entry we just created/updated!");
		goto lock_fail;
	}

	switch (mode) {
	case IPV6_TO_IPV4:
		out->L3_PROTOCOL = PF_INET;
		if (!switch_l4_proto(in->L4_PROTOCOL, &out->L4_PROTOCOL))
			goto lock_fail;
		out->ipv4_src_addr = bib->ipv4.address;
		out->src_port = cpu_to_be16(bib->ipv4.l4_id);
		if (!addr_6to4(&in->ipv6_dst_addr, &prefix, &out->ipv4_dst_addr))
			goto lock_fail;
		out->dst_port = in->dst_port;
		break;

	case IPV4_TO_IPV6:
		out->L3_PROTOCOL = PF_INET6;
		if (!switch_l4_proto(in->L4_PROTOCOL, &out->L4_PROTOCOL))
			goto lock_fail;
		if (!addr_4to6(&in->ipv4_src_addr, &prefix, &out->ipv6_src_addr))
			goto lock_fail;
		out->src_port = in->src_port;
		out->ipv6_dst_addr = bib->ipv6.address;
		out->dst_port = cpu_to_be16(bib->ipv6.l4_id);
		break;

	default:
		log_crit(ERR_TRANSLATION_MODE, "Unknown translation mode: %d.", mode);
		goto lock_fail;
	}

	spin_unlock_bh(&bib_session_lock);
	log_debug("Done step 3.");
	return true;

lock_fail:
	spin_unlock_bh(&bib_session_lock);
	return false;
}

static bool tuple3(struct nf_conntrack_tuple *in, struct nf_conntrack_tuple *out,
		enum translation_mode mode)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;

	log_debug("Step 3: Computing the Outgoing Tuple");

	if (!pool6_peek(&prefix)) {
		log_err(ERR_POOL6_EMPTY, "The IPv6 pool is empty. Cannot translate.");
		return false;
	}

	spin_lock_bh(&bib_session_lock);
	bib = bib_get(in);
	if (!bib) {
		log_crit(ERR_MISSING_BIB, "Could not find the BIB entry we just created/updated!");
		goto lock_fail;
	}

	switch (mode) {
	case IPV6_TO_IPV4:
		out->L3_PROTOCOL = PF_INET;
		out->L4_PROTOCOL = IPPROTO_ICMP;
		out->ipv4_src_addr = bib->ipv4.address;
		if (!addr_6to4(&in->ipv6_dst_addr, &prefix, &out->ipv4_dst_addr))
			goto lock_fail;
		out->icmp_id = cpu_to_be16(bib->ipv4.l4_id);
		break;

	case IPV4_TO_IPV6:
		out->L3_PROTOCOL = PF_INET6;
		out->L4_PROTOCOL = IPPROTO_ICMPV6;
		if (!addr_4to6(&in->ipv4_src_addr, &prefix, &out->ipv6_src_addr))
			goto lock_fail;
		out->ipv6_dst_addr = bib->ipv6.address;
		out->icmp_id = cpu_to_be16(bib->ipv6.l4_id);
		break;

	default:
		log_crit(ERR_TRANSLATION_MODE, "Programming error: Unknown translation mode: %d.", mode);
		goto lock_fail;
	}

	spin_unlock_bh(&bib_session_lock);
	log_debug("Done step 3.");
	return true;

lock_fail:
	spin_unlock_bh(&bib_session_lock);
	return false;
}

bool compute_out_tuple_6to4(struct nf_conntrack_tuple *in, struct sk_buff *skb_in,
		struct nf_conntrack_tuple *out)
{
	switch (in->L4_PROTOCOL) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		return tuple5(in, out, IPV6_TO_IPV4);
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return is_icmp6_info(icmp6_hdr(skb_in)->icmp6_type)
				? tuple3(in, out, IPV6_TO_IPV4)
				: tuple5(in, out, IPV6_TO_IPV4);
	default:
		log_crit(ERR_L4PROTO, "Unknown transport protocol: %u.", in->L4_PROTOCOL);
		return false;
	}
}

bool compute_out_tuple_4to6(struct nf_conntrack_tuple *in, struct sk_buff *skb_in,
		struct nf_conntrack_tuple *out)
{
	switch (in->L4_PROTOCOL) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		return tuple5(in, out, IPV4_TO_IPV6);
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return is_icmp_info(icmp_hdr(skb_in)->type)
				? tuple3(in, out, IPV4_TO_IPV6)
				: tuple5(in, out, IPV4_TO_IPV6);
	default:
		log_crit(ERR_L4PROTO, "Unknown transport protocol: %u.", in->L4_PROTOCOL);
		return false;
	}
}
