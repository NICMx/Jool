#ifndef _JOOL_MOD_POOL6_H
#define _JOOL_MOD_POOL6_H

/**
 * @file
 * The pool of IPv6 prefixes.
 */

#include "nat64/common/types.h"

struct pool6;

int pool6_init(struct pool6 **pool);
void pool6_get(struct pool6 *pool);
void pool6_put(struct pool6 *pool);

int pool6_find(struct pool6 *pool, const struct in6_addr *addr,
		struct ipv6_prefix *prefix);
int pool6_peek(struct pool6 *pool, struct ipv6_prefix *result);
bool pool6_contains(struct pool6 *pool, struct in6_addr *addr);

int pool6_add(struct pool6 *pool, struct ipv6_prefix *prefix);
int pool6_add_str(struct pool6 *pool, char *prefix_strings[], int prefix_count);
int pool6_rm(struct pool6 *pool, struct ipv6_prefix *prefix);
int pool6_flush(struct pool6 *pool);

int pool6_foreach(struct pool6 *pool,
		int (*func)(struct ipv6_prefix *, void *), void *arg,
		struct ipv6_prefix *offset);
int pool6_count(struct pool6 *pool, __u64 *result);
bool pool6_is_empty(struct pool6 *pool);
void pool6_print_refcount(struct pool6 *pool);

#endif /* _JOOL_MOD_POOL6_H */
