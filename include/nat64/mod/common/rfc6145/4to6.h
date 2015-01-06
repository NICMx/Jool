#ifndef _JOOL_MOD_TTP_4TO6_H
#define _JOOL_MOD_TTP_4TO6_H

/**
 * @file
 * Actual translation of packet contents from from IPv4 to IPv6.
 *
 * This is RFC 6145 sections 4.1, 4.2 and 4.3.
 */

#include "nat64/mod/common/rfc6145/common.h"

/**
 * Creates in "out" a packet which other functions will fill with the IPv6 version of the IPv4
 * packet "in".
 */
int ttp46_create_skb(struct sk_buff *in, struct sk_buff **out);
/**
 * Translates "in"'s IPv4 header into IPv6 and places the result in "out".
 */
int ttp46_ipv6(struct tuple *tuple6, struct sk_buff *in, struct sk_buff *out);
/**
 * Translates "in"'s ICMPv4 header and payload into ICMPv6 and payload, and places the result in
 * "out".
 */
int ttp46_icmp(struct tuple* tuple6, struct sk_buff *in, struct sk_buff *out);
/**
 * Translates "in"'s TCP header and payload, and places the result in "out".
 */
int ttp46_tcp(struct tuple *tuple6, struct sk_buff *in, struct sk_buff *out);
/**
 * Translates "in"'s UDP header and payload, and places the result in "out".
 */
int ttp46_udp(struct tuple *tuple6, struct sk_buff *in, struct sk_buff *out);

#endif /* _JOOL_MOD_TTP_4TO6_H */
