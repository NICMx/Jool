#ifndef _NF_NAT64_ICMP_WRAPPER_H
#define _NF_NAT64_ICMP_WRAPPER_H

#include "nat64/mod/packet.h"


/**
 * @file
 * Direct use of the icmp_send() and icmpv6_send() functions after the determine incoming tuple
 * step is bound to become a bug nest. That's because steps filtering through translate are reused
 * in hairpinning, so when an error occurs while translating a IPv4 packet, one cannot assume that
 * the resulting ICMP error will be a IPv4 one.
 *
 * In those situations, you can use this code instead. It transparently sends the correct ICMP
 * error no matter where you are.
 *
 * For the sake of consistency, use this module even if your code isn't reused in hairpinning,
 * please.
 */

typedef enum icmp_error_code {
	ICMPERR_SILENT,
	ICMPERR_ADDR_UNREACHABLE,
	ICMPERR_PROTO_UNREACHABLE,
	ICMPERR_HOP_LIMIT,
	ICMPERR_FRAG_NEEDED,
	ICMPERR_HDR_FIELD,
	ICMPERR_SRC_ROUTE,
	ICMPERR_FILTER,
} icmp_error_code;

/**
 * Wrapper for the icmp_send() and the icmpv6_send() functions.
 */
void icmp64_send(struct sk_buff *skb, icmp_error_code code, __be32 info);


#endif /* _NF_NAT64_ICMP_WRAPPER_H */
