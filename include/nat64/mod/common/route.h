#ifndef _JOOL_MOD_ROUTE_H
#define _JOOL_MOD_ROUTE_H

#include "nat64/mod/common/packet.h"

/**
 * Routes @in's outgoing packet.
 *
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4
 * out-routing function.
 */
int __route4(struct packet *in, __be32 daddr, __u8 tos, __u8 proto);

/**
 * Use this function instead of __route4() when you know the rest of the
 * args can be extracted safely from @out (ie. they have been initialized).
 */
int route4(struct packet *in, struct packet *out);

/**
 * Same as route4(), except for IPv6.
 */
int route6(struct packet *pkt);

/**
 * Used when you want to send an ICMP error, indicates where the original packet came from.
 */
int route4_input(struct packet *pkt);

#endif /* _JOOL_MOD_ROUTE_H */
