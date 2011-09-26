/*
 * Definitions and Declarations for tuples as described in the NAT64's RFC6146.
 *
 * 26 Sep 2011: Juan Antonio Osorio <jaosorior@gmail.com>
 */

#ifndef _NF_NAT64_TUPLE_H
#define _NF_NAT64_TUPLE_H
#include <linux/types.h>

/*
 * The 3-Tuple as described in the RFC is:
 *
 * 	"The tuple (source IP address, destination IP address, ICMP Identifier).
 * 	A 3-tuple uniquely identifies an ICMP Query session. When an ICMP Query
 * 	session flows through a NAT64, each session has two different 3-tuples: one
 * 	with IPv4 addresses and one with IPv6 addresses."
 *
 */
struct nf_nat64_3tuple {
	union nf_inet_addr src, dst;

	struct {
		__be16 id;
	} icmp;

	u_int8_t family;
};

/*
 * The 5-Tuple as described in the RFC is:
 *
 * 	"The tuple (source IP address, source port, destinaion IP address,
 * 	destination port, transport protocol). A 5-tuple uniquely identifies
 * 	a UDP/TCP session. When a UDP/TCP session flows through a ANT64, each
 * 	session has two different 5-tuples: one with IPv4 addresses and one with
 * 	IPv6 addresses."
 *
 * nf_conntrack_tuple defined in net/netfilter/nf_conntrack_tuple is compliant
 * to this specification.
 */
#include <net/netfilter/nf_conntrack_tuple.h>

#endif /* _NF_NAT64_TUPLE_H */
