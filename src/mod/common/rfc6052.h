#ifndef _JOOL_MOD_RFC6052_H
#define _JOOL_MOD_RFC6052_H

/**
 * @file
 * The algorithm defined in RFC 6052 (http://tools.ietf.org/html/rfc6052).
 */

#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "common/types.h"


/**
 * Translates @src into an IPv4 address and returns it as @dst.
 *
 * In other words, removes @prefix from @src. The result will be 32 bits of
 * address.
 */
int rfc6052_6to4(struct ipv6_prefix const *prefix, struct in6_addr const *src,
		struct in_addr *dst);

/**
 * Translates @src into an IPv6 address and returns it as @dst.
 *
 * In other words, adds @prefix to @src. The result will be 128 bits of address.
 */
int rfc6052_4to6(struct ipv6_prefix const *prefix, struct in_addr const *src,
		struct in6_addr *dst);

#define RFC6052_6TO4(state, src, dst) \
	rfc6052_6to4(&(state)->jool.global->cfg.pool6.prefix, src, dst)
#define RFC6052_4TO6(state, src, dst) \
	rfc6052_4to6(&(state)->jool.global->cfg.pool6.prefix, src, dst)

#endif /* _JOOL_MOD_RFC6052_H */
