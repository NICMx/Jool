#ifndef _JOOL_MOD_RFC6145_6TO4_H
#define _JOOL_MOD_RFC6145_6TO4_H

/**
 * @file
 * Actual translation of packet contents from from IPv6 to IPv4.
 *
 * This is RFC 6145 sections 5.1, 5.1.1, 5.2 and 5.3.
 */

#include "nat64/mod/common/rfc6145/common.h"

/**
 * Creates in "out" a packet which other functions will fill with the IPv4 version of the IPv6
 * packet "in".
 */
verdict ttp64_create_skb(struct sk_buff *in, struct sk_buff **out);
/**
 * Translates "in"'s IPv6 header into IPv4 and places the result in "out".
 */
verdict ttp64_ipv4(struct tuple *tuple4, struct sk_buff *in, struct sk_buff *out);
/**
 * Translates "in"'s ICMPv6 header and payload into ICMPv4 and payload, and places the result in
 * "out".
 */
verdict ttp64_icmp(struct tuple* tuple4, struct sk_buff *in, struct sk_buff *out);
/**
 * Translates "in"'s TCP header and payload, and places the result in "out".
 */
verdict ttp64_tcp(struct tuple *tuple4, struct sk_buff *in, struct sk_buff *out);
/**
 * Translates "in"'s UDP header and payload, and places the result in "out".
 */
verdict ttp64_udp(struct tuple *tuple4, struct sk_buff *in, struct sk_buff *out);

#endif /* _JOOL_MOD_RFC6145_6TO4_H */
