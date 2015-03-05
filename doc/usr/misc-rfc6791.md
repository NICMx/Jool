---
layout: documentation
title: Documentation - RFC 6791
---

[Documentation](doc-index.html) > [Runs](doc-index.html#runs) > [SIIT](mod-run-vanilla.html) > RFC 6791

# RFC 6791

Suppose _n4_ is trying to reach _n6_, but there is a problem (eg. the packet is too big), and _R_ sends _n4_ an ICMP error. _T_ is translating using prefix 2001:db8::/64.

![Figure 1 - Network](images/network/rfc6791.svg)

_R_'s packet will have the following addresses:

| Source  | Destination          |
|---------+----------------------|
| 4000::1 | 2001:db8::192.0.2.13 |

_T_ is in trouble because the source address of the packet lacks the translation prefix, so an IPv4 address cannot be extracted from it.

Normally, you don't have many IPv4 addresses, so it's not reasonable to grant one to every node in your IPv6 side. Due to their generally forwarding-only purpose, routers are good candidates for untranslatable addresses. On the other hand, ICMP errors are important, and a NAT64 should not drop it simply because it comes from a router.

Stateful NAT64s do not have this problem because they [render every IPv6 address translatable](intro-nat64.html#stateful-nat64) (since all IPv6 nodes are sharing the NAT64's IPv4 addresses). To sort things out, an SIIT module is supposed to keep a pool of reserved addresses. Upon receiving an ICMP error with an untranslatable source, Jool should assign a random one from this pool.

Please consider the following quotes from [RFC 6791](https://tools.ietf.org/html/rfc6791) while deciding the size and addresses of your RFC 6791 pool:

	The source address used SHOULD NOT cause the ICMP packet to be
	discarded.  It SHOULD NOT be drawn from [RFC1918] or [RFC6598]
	address space, because that address space is likely to be subject to
	unicast Reverse Path Forwarding (uRPF) [RFC3704] filtering.

Because it is in our best interests that the examples shown in the walkthroughs work, Jool currently does not try to ban you from using the above addresses. Please exercise caution.

	Another consideration for source selection is that it should be
	possible for the IPv4 recipients of the ICMP message to be able to
	distinguish between different IPv6 network origination of ICMPv6
	messages (for example, to support a traceroute diagnostic utility
	that provides some limited network-level visibility across the IPv4/
	IPv6 translator).  This consideration implies that an IPv4/IPv6
	translator needs to have a pool of IPv4 addresses for mapping the
	source address of ICMPv6 packets generated from different origins, or
	to include the IPv6 source address information for mapping the source
	address by others means.  Currently, the TRACEROUTE and MTR [MTR] are
	the only consumers of translated ICMPv6 messages that care about the
	ICMPv6 source address.
	
	(...)

	If a pool of public IPv4 addresses is configured on the translator,
	it is RECOMMENDED to randomly select the IPv4 source address from the
	pool.  Random selection reduces the probability that two ICMP
	messages elicited by the same TRACEROUTE might specify the same
	source address and, therefore, erroneously present the appearance of
	a routing loop.

The [SIIT walkthrough](mod-run-vanilla.html) shows how to set the pool during a modprobe. You can also edit it later via the [userspace application](usr-flags-error-addresses.html).

