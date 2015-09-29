#ifndef _JOOL_MOD_ROUTE_H
#define _JOOL_MOD_ROUTE_H

#include "nat64/mod/common/packet.h"

/**
 * Routes @in's outgoing packet.
 *
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4
 * out-routing function.
 */
struct dst_entry *__route4(__be32 daddr, __u8 tos, __u8 proto, __u32 mark,
		struct packet *pkt);

/**
 * Use this function instead of __route4() when you know the rest of the
 * args can be extracted safely from @pkt (ie. they have been initialized).
 */
struct dst_entry *route4(struct packet *pkt);

/**
 * Same as route4(), except for IPv6.
 */
struct dst_entry *route6(struct packet *pkt);

/**
 * Protocol independent version of route4() and route6().
 * ie. it's just a wrapper.
 */
struct dst_entry *route(struct packet *pkt);

/**
 * Used when you want to send an ICMP error, indicates where the original packet came from.
 */
int route4_input(struct packet *pkt);

#endif /* _JOOL_MOD_ROUTE_H */
