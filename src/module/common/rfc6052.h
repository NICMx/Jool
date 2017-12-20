#ifndef _JOOL_MOD_RFC6052_H
#define _JOOL_MOD_RFC6052_H

/**
 * The algorithm defined in RFC 6052 (http://tools.ietf.org/html/rfc6052).
 */

#include "xlation.h"

/**
 * Translates @src into an IPv4 address and returns it as @dst.
 *
 * In other words, removes the pool6 prefix from @src. The result will be 32
 * bits of address.
 */
int rfc6052_6to4(struct xlation *state,
		const struct in6_addr *src,
		struct in_addr *dst);
/**
 * Translates @src into an IPv6 address and returns it as @dst.
 *
 * In other words, adds the pool6 prefix to @src. The result will be 128 bits of
 * address.
 */
int rfc6052_4to6(struct xlation *state,
		const struct in_addr *src,
		struct in6_addr *dst);

#endif /* _JOOL_MOD_RFC6052_H */
