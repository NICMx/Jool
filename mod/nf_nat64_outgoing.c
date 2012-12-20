#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "nf_nat64_rfc6052.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_outgoing.h"


// TODO (config) hay 4 prefijos hardcodeados aquí.

bool nat64_compute_outgoing_tuple_tuple5(struct nf_conntrack_tuple *outgoing,
		struct nf_conntrack_tuple *incoming, enum translation_mode translationMode)
{
	struct bib_entry *bib;

	outgoing->L3_PROTOCOL = incoming->L3_PROTOCOL;
	outgoing->L4_PROTOCOL = incoming->L4_PROTOCOL;

	switch (translationMode) {
	case IPV6_TO_IPV4:
		bib = nat64_get_bib_entry(incoming);
		if (!bib) {
			log_err("Programming error: Could not find the BIB entry we just created!");
			return false;
		}

		outgoing->ipv4_src_addr = bib->ipv4.address;
		outgoing->src_port = bib->ipv4.pi.port;
		outgoing->ipv4_dst_addr = nat64_extract_ipv4(&incoming->ipv6_dst_addr, 96);
		outgoing->dst_port = incoming->dst_port;
		break;

	case IPV4_TO_IPV6:
		bib = nat64_get_bib_entry(incoming);
		if (!bib) {
			log_err("Could not find the BIB entry we just created!");
			return false;
		}

		outgoing->ipv6_src_addr = nat64_append_ipv4(&incoming->ipv6_dst_addr,
				&incoming->ipv4_dst_addr, 96);
		outgoing->src_port = bib->ipv6.pi.port;
		outgoing->ipv6_src_addr = bib->ipv6.address;
		outgoing->src_port = bib->ipv6.pi.port;
		break;

	default:
		log_crit("Programming error: Unknown translation mode: %d.", translationMode);
		return false;
	}

	return true;
}

bool nat64_compute_outgoing_tuple_tuple3(struct nf_conntrack_tuple *outgoing,
		struct nf_conntrack_tuple *incoming, enum translation_mode translationMode)
{
	struct bib_entry *bib;

	outgoing->L3_PROTOCOL = incoming->L3_PROTOCOL;

	switch (translationMode) {
	case IPV6_TO_IPV4:
		outgoing->L4_PROTOCOL = IPPROTO_ICMP;

		bib = nat64_get_bib_entry(incoming);
		if (!bib) {
			log_err("Could not find the BIB entry we just created!");
			return false;
		}

		outgoing->ipv4_src_addr = bib->ipv4.address;
		outgoing->ipv4_dst_addr = nat64_extract_ipv4(&incoming->ipv6_dst_addr, 96);
		outgoing->icmp_id = bib->ipv4.pi.id;
		break;

	case IPV4_TO_IPV6:
		outgoing->L4_PROTOCOL = IPPROTO_ICMPV6;

		bib = nat64_get_bib_entry(incoming);
		if (!bib) {
			log_err("Could not find the BIB entry we just created!");
			return false;
		}

		outgoing->ipv6_src_addr = nat64_append_ipv4(&incoming->ipv6_dst_addr,
				&incoming->ipv4_dst_addr, 96);
		outgoing->ipv6_dst_addr = bib->ipv6.address;
		outgoing->icmp_id = bib->ipv6.pi.id;
		break;

	default:
		log_crit("Programming error: Unknown translation mode: %d.", translationMode);
		return false;
	}

	return true;
}
