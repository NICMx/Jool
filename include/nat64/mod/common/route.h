#ifndef _JOOL_MOD_ROUTE_H
#define _JOOL_MOD_ROUTE_H

#include <linux/skbuff.h>

/**
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4 routing function.
 *
 * Routes the skb described by the arguments. Returns the 'destination entry' the kernel needs
 * to know which interface the skb should be forwarded through.
 *
 * This function assumes "skb" isn't fragmented.
 */
int route4(struct sk_buff *skb);

/**
 * Same as route_ipv4(), except for IPv6.
 */
int route6(struct sk_buff *skb);

/**
 * Protocol independent version of the previous two functions.
 * ie. it's just a wrapper.
 */
int route(struct sk_buff *skb);

#endif /* _JOOL_MOD_ROUTE_H */
