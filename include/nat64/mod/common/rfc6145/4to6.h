#ifndef _JOOL_MOD_RFC6145_4TO6_H
#define _JOOL_MOD_RFC6145_4TO6_H

/**
 * @file
 * Actual translation of packet contents from from IPv4 to IPv6.
 *
 * This is RFC 6145 sections 4.1, 4.2 and 4.3.
 */

#include "nat64/mod/common/rfc6145/common.h"

/**
 * Creates in "state->out.skb" a packet which other functions will fill with the
 * IPv6 version of the IPv4 packet "in".
 */
verdict ttp46_create_skb(struct xlation *state);
/**
 * Translates "state->in"'s IPv4 header into IPv6 and places the result in
 * "state->out".
 */
verdict ttp46_ipv6(struct xlation *state);
/**
 * Translates "state->in"'s ICMPv4 header and payload, and places the result in
 * "state->out".
 */
verdict ttp46_icmp(struct xlation *state);
/**
 * Translates "state->in"'s TCP header and payload, and places the result in
 * "state->out".
 */
verdict ttp46_tcp(struct xlation *state);
/**
 * Translates "state->in"'s UDP header and payload, and places the result in
 * "state->out".
 */
verdict ttp46_udp(struct xlation *state);

#endif /* _JOOL_MOD_RFC6145_4TO6_H */
