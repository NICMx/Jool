#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/icmp.h>
#include <net/netfilter/nf_conntrack.h>

#include "nf_nat64_types.h"
#include "external_stuff.h"
#include "nf_nat64_determine_incoming_tuple.h"


/**
 * Returns whether the NAT64 can handle packets using the "l4protocol" transport protocol when the
 * network protocol is IPv4.
 *
 * @param transport protocol id to test.
 * @return whether the NAT64 can handle packets using the "l4protocol" transport protocol when the
 *		network protocol is IPv4.
 */
static inline bool is_l4_protocol_supported_ipv4(u_int8_t l4protocol)
{
	return l4protocol == IPPROTO_TCP
			|| l4protocol == IPPROTO_UDP
			|| l4protocol == IPPROTO_ICMP;
}

/**
 * Returns whether the NAT64 can handle packets using the "l4protocol" transport protocol when the
 * network protocol is IPv6.
 *
 * @param transport protocol id to test.
 * @return whether the NAT64 can handle packets using the "l4protocol" transport protocol when the
 *		network protocol is IPv6.
 */
static inline bool is_l4_protocol_supported_ipv6(u_int8_t l4protocol)
{
	return l4protocol == IPPROTO_TCP
			|| l4protocol == IPPROTO_UDP
			|| l4protocol == IPPROTO_ICMPV6;
}

bool nat64_determine_incoming_tuple(struct sk_buff *skb, struct nf_conntrack_tuple **result)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	enum ip_conntrack_dir dir;
	struct nf_conntrack_tuple *tuple;

	pr_debug("Step 1: Determining the Incoming Tuple");

	// Ask conntrack to do the work for us.
	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL)
		return false;
	dir = CTINFO2DIR(ctinfo);
	tuple = &ct->tuplehash[dir].tuple;

	// Just to debug...
	nf_ct_dump_tuple(tuple);

	// Now perform the only validation defined in this step.
	switch (tuple->l3_protocol) {
	case NFPROTO_IPV4:
		if (!is_l4_protocol_supported_ipv4(tuple->l4_protocol)) {
			nat64_send_icmp_error(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
			goto unsupported_l4_protocol;
		}
		break;
	case NFPROTO_IPV6:
		if (!is_l4_protocol_supported_ipv6(tuple->l4_protocol)) {
			// TODO por qué se envía un paquete de ICMPv4 si la red objetivo es IPv6?
			nat64_send_icmp_error(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
			goto unsupported_l4_protocol;
		}
		break;
	default:
		goto unsupported_l3_protocol;
	}

	*result = tuple;
	pr_debug("Done step 1.");
	return true;

unsupported_l3_protocol:
	printk(KERN_WARNING "Unsupported L3 protocol (%u). Dropping packet...", tuple->l3_protocol);
	return false;

unsupported_l4_protocol:
	printk(KERN_WARNING "Unsupported L4 protocol (%u). Dropping packet...", tuple->l4_protocol);
	return false;
}
