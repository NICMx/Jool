#ifndef _JOOL_MOD_RFC6145_6TO4_H
#define _JOOL_MOD_RFC6145_6TO4_H

/**
 * @file
 * Actual translation of packet contents from from IPv6 to IPv4.
 *
 * This is RFC 6145 sections 5.1, 5.1.1, 5.2 and 5.3. Not to be confused with
 * the technology called "6to4", which is RFC 3056.
 */

#include "nat64/mod/common/translation_state.h"

/**
 * Creates in "state->out.skb" a packet which other functions will fill with the
 * IPv4 version of the IPv6 packet "state->in.skb".
 */
verdict ttp64_create_skb(struct xlation *state);
/**
 * Translates "state->in"'s IPv6 header into IPv4 and places the result in
 * "state->out".
 */
verdict ttp64_ipv4(struct xlation *state);
/**
 * Translates "state->in"'s ICMPv6 header and payload, and places the result in
 * "state->out".
 */
verdict ttp64_icmp(struct xlation *state);
/**
 * Translates "state->in"'s TCP header and payload, and places the result in
 * "state->out".
 */
verdict ttp64_tcp(struct xlation *state);
/**
 * Translates "state->in"'s UDP header and payload, and places the result in
 * "state->out".
 */
verdict ttp64_udp(struct xlation *state);

__u8 ttp64_xlat_tos(struct global_config_usr *config, struct ipv6hdr *hdr);
__u8 ttp64_xlat_proto(struct ipv6hdr *hdr);

#endif /* _JOOL_MOD_RFC6145_6TO4_H */
