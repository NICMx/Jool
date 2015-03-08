#ifndef _JOOL_MOD_ROUTE_H
#define _JOOL_MOD_ROUTE_H

#include "nat64/mod/common/packet.h"

/**
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4 out-routing function.
 *
 * Routes pkt. Fills pkt->skb with the resulting device and destination.
 */
int route4(struct packet *pkt);

/**
 * Same as route4(), except the layer-4 information used for routing will be extracted from "in"
 * instead of "out".
 *
 * The packet being routed is "out".
 */
int __route4(struct packet *in, struct packet *out);

/**
 * Same as route4(), except for IPv6.
 */
int route6(struct packet *pkt);

/**
 * Protocol independent version of route4() and route6().
 * ie. it's just a wrapper.
 */
int route(struct packet *pkt);

/**
 * Used when you want to send an ICMP error, indicates where the original packet came from.
 */
int route4_input(struct packet *pkt);

#endif /* _JOOL_MOD_ROUTE_H */
