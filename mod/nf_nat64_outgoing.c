#include "nf_nat64_outgoing.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "nf_nat64_rfc6052.h"
#include "nf_nat64_pool6.h"
#include "nf_nat64_bib.h"


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
		log_crit("Programming error: Unknown l4 protocol: %u.", proto_in);
		return false;
	}
}

static bool tuple5(struct nf_conntrack_tuple *in, struct nf_conntrack_tuple *out,
		enum translation_mode mode)
{
	struct bib_entry bib;
	struct ipv6_prefix prefix;

	log_debug("Step 3: Computing the Outgoing Tuple");

	if (!nat64_get_bib_entry(in, &bib)) {
		log_err("Could not find the BIB entry we just created/updated!");
		return false;
	}

	if (!pool6_peek(&prefix)) {
		log_warning("The IPv6 pool is empty. Cannot translate.");
		return false;
	}

	switch (mode) {
	case IPV6_TO_IPV4:
		out->L3_PROTOCOL = PF_INET;
		if (!switch_l4_proto(in->L4_PROTOCOL, &out->L4_PROTOCOL))
			return false;
		out->ipv4_src_addr = bib.ipv4.address;
		out->src_port = cpu_to_be16(bib.ipv4.l4_id);
		if (!nat64_extract_ipv4(&in->ipv6_dst_addr, &prefix, &out->ipv4_dst_addr))
			return false;
		out->dst_port = in->dst_port;
		break;

	case IPV4_TO_IPV6:
		out->L3_PROTOCOL = PF_INET6;
		if (!switch_l4_proto(in->L4_PROTOCOL, &out->L4_PROTOCOL))
			return false;
		if (!nat64_append_ipv4(&in->ipv4_src_addr, &prefix, &out->ipv6_src_addr))
			return false;
		out->src_port = cpu_to_be16(bib.ipv6.l4_id);
		out->ipv6_src_addr = bib.ipv6.address;
		out->src_port = cpu_to_be16(bib.ipv6.l4_id);
		break;

	default:
		log_crit("Programming error: Unknown translation mode: %d.", mode);
		return false;
	}

	log_debug("Done step 3.");
	return true;
}

static bool tuple3(struct nf_conntrack_tuple *in, struct nf_conntrack_tuple *out,
		enum translation_mode mode)
{
	struct bib_entry bib;
	struct ipv6_prefix prefix;

	log_debug("Step 3: Computing the Outgoing Tuple");

	if (!nat64_get_bib_entry(in, &bib)) {
		log_err("Could not find the BIB entry we just created/updated!");
		return false;
	}

	if (!pool6_peek(&prefix)) {
		log_warning("The IPv6 pool is empty. Cannot translate.");
		return false;
	}

	switch (mode) {
	case IPV6_TO_IPV4:
		out->L3_PROTOCOL = PF_INET;
		out->L4_PROTOCOL = IPPROTO_ICMP;
		out->ipv4_src_addr = bib.ipv4.address;
		if (!nat64_extract_ipv4(&in->ipv6_dst_addr, &prefix, &out->ipv4_dst_addr))
			return false;
		out->icmp_id = cpu_to_be16(bib.ipv4.l4_id);
		break;

	case IPV4_TO_IPV6:
		out->L3_PROTOCOL = PF_INET6;
		out->L4_PROTOCOL = IPPROTO_ICMPV6;
		if (!nat64_append_ipv4(&in->ipv4_src_addr, &prefix, &out->ipv6_src_addr))
			return false;
		out->ipv6_dst_addr = bib.ipv6.address;
		out->icmp_id = cpu_to_be16(bib.ipv6.l4_id);
		break;

	default:
		log_crit("Programming error: Unknown translation mode: %d.", mode);
		return false;
	}

	log_debug("Done step 3.");
	return true;
}

bool compute_outgoing_tuple_6to4(struct nf_conntrack_tuple *in, struct sk_buff *skb_in,
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
		log_crit("Programming error: Unknown l4 protocol: %u.", in->L4_PROTOCOL);
		return false;
	}
}

bool compute_outgoing_tuple_4to6(struct nf_conntrack_tuple *in, struct sk_buff *skb_in,
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
		log_crit("Programming error: Unknown l4 protocol: %u.", in->L4_PROTOCOL);
		return false;
	}
}
