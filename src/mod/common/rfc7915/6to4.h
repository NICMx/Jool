#ifndef SRC_MOD_COMMON_RFC7915_6TO4_H_
#define SRC_MOD_COMMON_RFC7915_6TO4_H_

/**
 * @file
 * Actual translation of packet contents from from IPv6 to IPv4.
 *
 * This is RFC 7915 sections 5.1, 5.1.1, 5.2 and 5.3. Not to be confused with
 * the technology called "6to4", which is RFC 3056.
 */

#include "mod/common/translation_state.h"

/**
 * Creates in "state->out.skb" a packet which other functions will fill with the
 * IPv4 version of the IPv6 packet "state->in.skb".
 */
verdict ttp64_alloc_skb(struct xlation *state);
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

#endif /* SRC_MOD_COMMON_RFC7915_6TO4_H_ */
