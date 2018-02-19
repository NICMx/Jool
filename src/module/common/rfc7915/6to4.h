#ifndef _JOOL_MOD_RFC6145_6TO4_H
#define _JOOL_MOD_RFC6145_6TO4_H

/**
 * Actual translation of packet contents from from IPv6 to IPv4.
 *
 * Overall, this is RFC 6145 section 5. Not to be confused with the technology
 * called "6to4", which is RFC 3056.
 */

#include "xlation.h"

/**
 * Allocates and readies the meta fields of the skb that is going to hold the
 * translated IPv4 packet (@state->out.skb).
 */
int ttp64_create_skb(struct xlation *state);
/**
 * Translates @state->in's IPv6 header into IPv4 and places the result in
 * @state->out.
 */
int ttp64_ipv4(struct xlation *state);
/**
 * Translates @state->in's ICMPv6 header and payload, and places the result in
 * @state->out.
 */
int ttp64_icmp(struct xlation *state);
/**
 * Translates @state->in's TCP header and payload, and places the result in
 * @state->out.
 */
int ttp64_tcp(struct xlation *state);
/**
 * Translates @state->in's UDP header and payload, and places the result in
 * @state->out.
 */
int ttp64_udp(struct xlation *state);

__u8 ttp64_xlat_proto(struct ipv6hdr *hdr);

#endif /* _JOOL_MOD_RFC6145_6TO4_H */
