#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "nf_nat64_rfc6052.h"
#include "nf_nat64_pool6.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_outgoing.h"


static bool tuple5(struct nf_conntrack_tuple *incoming, struct nf_conntrack_tuple *outgoing,
		enum translation_mode translationMode)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;

	log_debug("Step 3: Computing the Outgoing Tuple");

	outgoing->L3_PROTOCOL = incoming->L3_PROTOCOL;
	outgoing->L4_PROTOCOL = incoming->L4_PROTOCOL;

	bib = nat64_get_bib_entry(incoming);
	if (!bib) {
		log_err("Could not find the BIB entry we just created!");
		return false;
	}

	if (!pool6_peek(&prefix)) {
		log_warning("The IPv6 pool is empty. Cannot translate.");
		return false;
	}

	switch (translationMode) {
	case IPV6_TO_IPV4:
		outgoing->ipv4_src_addr = bib->ipv4.address;
		outgoing->src_port = bib->ipv4.pi.port;
		if (!nat64_extract_ipv4(&incoming->ipv6_dst_addr, &prefix, &outgoing->ipv4_dst_addr))
			return false;
		outgoing->dst_port = incoming->dst_port;
		break;

	case IPV4_TO_IPV6:
		if (!nat64_append_ipv4(&incoming->ipv4_src_addr, &prefix, &outgoing->ipv6_src_addr))
			return false;
		outgoing->src_port = bib->ipv6.pi.port;
		outgoing->ipv6_src_addr = bib->ipv6.address;
		outgoing->src_port = bib->ipv6.pi.port;
		break;

	default:
		log_crit("Programming error: Unknown translation mode: %d.", translationMode);
		return false;
	}

	log_debug("Done step 3.");
	return true;
}

static bool tuple3(struct nf_conntrack_tuple *incoming, struct nf_conntrack_tuple *outgoing,
		enum translation_mode translationMode)
{
	struct bib_entry *bib;
	struct ipv6_prefix prefix;

	log_debug("Step 3: Computing the Outgoing Tuple");

	outgoing->L3_PROTOCOL = incoming->L3_PROTOCOL;

	bib = nat64_get_bib_entry(incoming);
	if (!bib) {
		log_err("Could not find the BIB entry we just created!");
		return false;
	}

	if (!pool6_peek(&prefix)) {
		log_warning("The IPv6 pool is empty. Cannot translate.");
		return false;
	}

	switch (translationMode) {
	case IPV6_TO_IPV4:
		outgoing->L4_PROTOCOL = IPPROTO_ICMP;
		outgoing->ipv4_src_addr = bib->ipv4.address;
		if (!nat64_extract_ipv4(&incoming->ipv6_dst_addr, &prefix, &outgoing->ipv4_dst_addr))
			return false;
		outgoing->icmp_id = bib->ipv4.pi.id;
		break;

	case IPV4_TO_IPV6:
		outgoing->L4_PROTOCOL = IPPROTO_ICMPV6;
		if (!nat64_append_ipv4(&incoming->ipv4_src_addr, &prefix, &outgoing->ipv6_src_addr))
			return false;
		outgoing->ipv6_dst_addr = bib->ipv6.address;
		outgoing->icmp_id = bib->ipv6.pi.id;
		break;

	default:
		log_crit("Programming error: Unknown translation mode: %d.", translationMode);
		return false;
	}

	log_debug("Done step 3.");
	return true;
}

static bool is_icmp6_info(__u8 type)
{
	return (type == ICMPV6_ECHO_REQUEST) || (type == ICMPV6_ECHO_REPLY);
}

static bool is_icmp_info(__u8 type)
{
	return (type == ICMP_ECHO) || (type == ICMP_ECHOREPLY);
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
		log_crit("  Programming error: Unknown l4 protocol: %u.", in->L4_PROTOCOL);
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
		log_crit("  Programming error: Unknown l4 protocol: %u.", in->L4_PROTOCOL);
		return false;
	}
}
