#ifndef _NF_NAT64_POOL6_H
#define _NF_NAT64_POOL6_H

/**
 * @file
 * The pool of IPv6 addresses.
 *
 * @author Alberto Leiva
 */

#include <linux/types.h>
#include <linux/in6.h>
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"


int pool6_init(char *pref_strs[], int pref_count);
void pool6_destroy(void);
/**
 * Removes all prefixes from the pool.
 */
int pool6_flush(void);

/**
 * You're not actually borrowing the prefix, so you don't have to return it.
 */
int pool6_get(struct in6_addr *addr, struct ipv6_prefix *prefix);
int pool6_peek(struct ipv6_prefix *result);
bool pool6_contains(struct in6_addr *addr);
/**
 * Return 0 if the prefix exists in the pool, otherwise return -ENOENT
 */
int pool6_contains_prefix(struct ipv6_prefix *prefix);

/**
 * A copy of prefix is stored, not prefix itself.
 */
int pool6_add(struct ipv6_prefix *prefix);
int pool6_remove(struct ipv6_prefix *prefix);

int pool6_for_each(int (*func)(struct ipv6_prefix *, void *), void * arg);
int pool6_count(__u64 *result);

#endif /* _NF_NAT64_POOL6_H */
