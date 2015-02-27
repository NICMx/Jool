#ifndef _JOOL_MOD_ROUTE_H
#define _JOOL_MOD_ROUTE_H

#include "nat64/mod/common/packet.h"

/**
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4 routing function.
 *
 * Routes the skb described by the arguments. Returns the 'destination entry' the kernel needs
 * to know which interface the skb should be forwarded through.
 *
 * This function assumes "skb" isn't fragmented.
 */
int route4(struct packet *pkt);

/**
 * Same as route_ipv4(), except for IPv6.
 */
int route6(struct packet *pkt);

/**
 * Protocol independent version of the previous two functions.
 * ie. it's just a wrapper.
 */
int route(struct packet *pkt);

/**
 * Used when you want to send an ICMP error, indicates where the original packet came from.
 */
int route4_input(struct packet *pkt);

#endif /* _JOOL_MOD_ROUTE_H */
