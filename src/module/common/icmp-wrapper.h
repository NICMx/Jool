#ifndef _JOOL_MOD_ICMP_WRAPPER_H
#define _JOOL_MOD_ICMP_WRAPPER_H

/**
 * @file
 * Direct use of the icmp_send() and icmpv6_send() functions after the determine
 * incoming tuple step is bound to become a bug nest. That's because steps
 * filtering through translate are reused in hairpinning, so when an error
 * occurs while translating a IPv4 packet, one cannot assume that the resulting
 * ICMP error will be a IPv4 one.
 *
 * In those situations, you can use this code instead. It transparently sends
 * the correct ICMP error no matter where you are.
 *
 * For the sake of consistency, and so the unit tests don't send bogus ICMP
 * errors left and right (because the unit tests use an impersonator no-op ICMP
 * wrapper), use this module even if your code isn't reused in hairpinning,
 * please.
 */

#include "packet.h"

typedef enum icmp_error_code {
	ICMPERR_SILENT,
	ICMPERR_ADDR_UNREACHABLE,
	ICMPERR_PORT_UNREACHABLE,
	ICMPERR_PROTO_UNREACHABLE,
	ICMPERR_HOP_LIMIT,
	ICMPERR_FRAG_NEEDED,
	ICMPERR_HDR_FIELD,
	ICMPERR_SRC_ROUTE,
	ICMPERR_FILTER,
} icmp_error_code;

/**
 * Wrappers for icmp_send() and icmpv6_send().
 */
void icmp64_send(struct packet *pkt, icmp_error_code code, __u32 info);
void icmp64_send_skb(struct sk_buff *skb, icmp_error_code error, __u32 info);

/**
 * Return the numbers of icmp error that was sent, also reset the static counter
 * This is only used in Unit Testing.
 */
int icmp64_pop(void);


#endif /* _JOOL_MOD_ICMP_WRAPPER_H */
