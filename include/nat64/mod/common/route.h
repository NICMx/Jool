#ifndef _JOOL_MOD_ROUTE_H
#define _JOOL_MOD_ROUTE_H

#include "nat64/mod/common/packet.h"

/**
 * Routes @skb (assuming @skb is an IPv4 packet).
 *
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4
 * routing function.
 */
struct dst_entry *__route4(struct net *ns, __be32 daddr, __u8 tos, __u8 proto,
		__u32 mark, struct sk_buff *skb);

/**
 * Use this function instead of __route4() when you know the rest of the
 * args can be extracted safely from @skb (ie. they have been initialized).
 */
struct dst_entry *route4(struct net *ns, struct packet *out);

struct dst_entry *__route6(struct net *ns, struct sk_buff *skb,
		l4_protocol proto);

/**
 * Same as route4(), except for IPv6.
 */
struct dst_entry *route6(struct net *ns, struct packet *out);

/**
 * Protocol independent version of route4() and route6().
 * ie. it's just a wrapper.
 */
struct dst_entry *route(struct net *ns, struct packet *pkt);

/**
 * Used when you want to send an ICMP error, indicates where the original packet
 * came from.
 */
int route4_input(struct packet *pkt);

#endif /* _JOOL_MOD_ROUTE_H */
