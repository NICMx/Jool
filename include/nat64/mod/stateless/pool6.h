#ifndef _JOOL_MOD_POOL6_H
#define _JOOL_MOD_POOL6_H

/**
 * @file
 * The pool of IPv6 prefixes.
 *
 * @author Alberto Leiva
 * @author Daniel Hdz Felix
 */

#include <linux/types.h>
#include <linux/in6.h>
#include "nat64/common/types.h"

/**
 * Readies the rest of this module for future use.
 *
 * @param pref_str string denoting the prefix the pool should start with.
 * @return result status (< 0 on error).
 */
int pool6_init(char *pref_str);
/**
 * Frees resources allocated by the pool.
 */
void pool6_destroy(void);

/**
 * Returns (in "prefix") the pool's prefix corresponding to "addr".
 *
 * Because you're not actually borrowing the prefix,
 * - you don't have to return it, and
 * - this function can also be described as a way to infer "addr"'s actual network prefix.
 */
int pool6_get(struct in6_addr *addr, struct ipv6_prefix *prefix);
/**
 * Returns (in "result") any prefix from the pool.
 */
int pool6_peek(struct ipv6_prefix *result);
/**
 * Returns whether "addr"'s network prefix belongs to the pool.
 */
bool pool6_contains(struct in6_addr *addr);

/**
 * Updates the current pool to "prefix".
 */
int pool6_update(struct ipv6_prefix *prefix);

/**
 * Executes the "func" function with the "arg" argument on the pool.
 */
int pool6_for_each(int (*func)(struct ipv6_prefix *, void *), void * arg);

#endif /* _JOOL_MOD_POOL6_H */
