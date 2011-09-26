/*
 * Definitions and Declarations for Binding Information Bases as described in
 * the NAT64's RFC6146.
 *
 * 26 Sep 2011: Juan Antonio Osorio Robles <jaosorior@gmail.com>
 */

#ifndef _NF_NAT64_BIB_H
#define _NF_NAT64_BIB_H
#include <linux/types.h>
/*
 * Binding Information Bases as described in the RFC:
 *
 * 	"A table of bindings kept by a NAT64."
 * 	"In the case of UDP and TCP BIBs, each BIB entry specifies a mapping
 * 	between the IPv6 transport address and an IPv4 transport address:"
 * 		(IPv6 address, port) <--> (IPv4 address, port)
 *
 * Session Tables as described in the RFC:
 * 
 * 	"Each entry keeps information on he state of the corresponding session. In
 * 	the TCP and UDP session tables, each entry specifies a mapping between
 * 	a pair of IPv6 transport addresses and a pair of IPv4 transport addresses:"
 *
 * 		(Source IPv6 address, port),(Destination IPv6 address, port)
 * 		<-->
 * 		(Source IPv4 address, port),(Destination IPv4 address, port)
 *
 * 		which we'll simply represent as:
 *
 * 			(X’,x),(Y’,y) <--> (T,t),(Z,z)
 *
 * 		Where:
 *
 * 			T = Unicast IPv4 address assigned to the NAT64.
 *
 * 			Y' = IPv6 representation of the IPv4 address Z.
 * 				Y' = (Pref64::/n) & (::Z)
 *
 * 			y = z
 *
 * 	For ICMP Queries:
 *
 * 		(Source IPv6 address, destination IPv6 address, ICMPv6 identifier)
 * 		<-->
 * 		(Source IPv4 address, destination IPv4 address, ICMPv4 identifier)
 *
 * 	Also, the Session Table Entry lifetime must be included.
 */


#endif /* _NF_NAT64_BIB_H */
