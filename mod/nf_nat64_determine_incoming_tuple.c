#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>

#include "nf_nat64_types.h"
#include "external_stuff.h"
#include "nf_nat64_determine_incoming_tuple.h"


/** A identifier of the IPv4 protocol. */
struct nf_conntrack_l3proto * l3proto_ip __read_mostly;
/** A identifier of the IPv6 protocol. */
struct nf_conntrack_l3proto * l3proto_ipv6 __read_mostly;

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

	pr_debug("Step 1: Determining the Incoming Tuple\n");

	// Conntrack already built the tuple, so just ask.
	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL) {
		pr_warning("Packet does not contain a conntrack entry. Dropping...\n");
		return false;
	}
	dir = CTINFO2DIR(ctinfo);
	tuple = &ct->tuplehash[dir].tuple;

	// Just to debug...
	nf_ct_dump_tuple(tuple);

	// Now perform the only validation defined in this step.
	switch (tuple->l3_protocol) {
	case NFPROTO_IPV4:
		if (!is_l4_protocol_supported_ipv4(tuple->l4_protocol)) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, 0);
			goto unsupported_l4_protocol;
		}
		break;
	case NFPROTO_IPV6:
		if (!is_l4_protocol_supported_ipv6(tuple->l4_protocol)) {
			icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0);
			goto unsupported_l4_protocol;
		}
		break;
	default:
		goto unsupported_l3_protocol;
	}

	*result = tuple;
	pr_debug("Done step 1.\n");
	return true;

unsupported_l3_protocol:
	pr_warning("Unsupported L3 protocol (%u). Dropping packet...\n", tuple->l3_protocol);
	return false;

unsupported_l4_protocol:
	pr_warning("Unsupported L4 protocol (%u). Dropping packet...\n", tuple->l4_protocol);
	return false;
}

bool nat64_determine_incoming_tuple_init(void)
{
	l3proto_ip = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV4);
	if (l3proto_ip == NULL) {
		pr_warning("NAT64: couldn't load IPv4 l3proto");
		return false;
	}

	l3proto_ipv6 = nf_ct_l3proto_find_get((u_int16_t) NFPROTO_IPV6);
	if (l3proto_ipv6 == NULL) {
		pr_warning("NAT64: couldn't load IPv6 l3proto");
		return false;
	}

	return true;
}

void nat64_determine_incoming_tuple_destroy(void)
{
	nf_ct_l3proto_put(l3proto_ip);
	nf_ct_l3proto_put(l3proto_ipv6);
}
