#ifndef _NF_NAT64_ICMP_WRAPPER_H
#define _NF_NAT64_ICMP_WRAPPER_H

#include "nat64/mod/packet.h"


/**
 * @file
 * Direct use of the icmp_send() and icmpv6_send() functions pretty much anywhere in Jool is bound
 * to become a bug nest, because they don't overly validate their parameters, and also because
 * NAT64 creates a scenario they are not prepared against.
 *
 * For one thing, Jool is attached to the LOCAL_OUT chain of Netfilter. Packets coming from the
 * localhost have a NULL dst, and the icmp functions above happily dereference that field.
 *
 * Another problem is hairpinning. When a IPv4 packet is being translated to IPv6, it might either
 * have originally been a IPv4 packet, or it might be a IPv6 packet doing a U-turn. In the latter
 * case, if a problem occurs, a IPv6 error message has to be answered, not a IPv4 one. And most of
 * Jool's code is reused during hairpinning.
 *
 * So it is convenient to have a one-liner that figures out the situation and behaves accordingly.
 *
 * Again, direct use of the kernel's icmp*_send() functions anywhere else in Jool is strongly
 * discouraged. Use the functions here instead.
 */

typedef enum icmp_error_code {
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
void icmp64_send(struct fragment *frag, icmp_error_code code, __be32 info);


#endif /* _NF_NAT64_ICMP_WRAPPER_H */
