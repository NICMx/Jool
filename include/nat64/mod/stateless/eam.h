#ifndef _JOOL_MOD_EAM_H
#define _JOOL_MOD_EAM_H

/*
 * address_mapping.h
 *
 *  Created on: Nov 25, 2014
 *  @author: Daniel Hdz Felix
 */

#include <linux/rbtree.h>
#include "nat64/common/config.h"
#include "nat64/common/types.h"

int eamt_init(void);
void eamt_destroy(void);

/**
 *	Insert IPv6 Prefix "ip6_pref" and IPv4 Prefix "ip4_pref" to the database, return zero if the
 *	insert was successful.
 *
 *	If the "ipX_pref" contains or is part of a prefix indexed in the databases, then returns error.
 */
int eamt_add(struct ipv6_prefix *ip6_pref, struct ipv4_prefix *ip4_pref);
int eamt_remove(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4);

/**
 * Look in the IPv4 address mapping table, if the IPv4 address "addr" is part of a prefix indexed
 * in the table, if "addr" exists, append the mapped IPv6 prefix to "result" and also append the
 * suffix from "addr" to "result".
 *
 * otherwise return error.
 */
int eamt_xlat_4to6(struct in_addr *addr, struct in6_addr *result);

/**
 * Look in the IPv6 address mapping table, if the IPv6 address "addr6" is part of a prefix indexed
 * in the table, if "addr6" exists, append the mapped IPv4 prefix to "result" and also append the
 * suffix from "addr6" to "result".
 *
 * otherwise return error.
 */
int eamt_xlat_6to4(struct in6_addr *addr6, struct in_addr *result);

/**
 * Empties the entire database.
 *
 * O(n), where n is the number of entries in the entire database.
 */
void eamt_flush(void);

/**
 * Returns true if "addr" is in the eam database, otherwise return false.
 */
bool eamt_contains6(struct in6_addr *addr);

/**
 * Returns true if "addr" is in the eam database, otherwise return false.
 */
bool eamt_contains4(__be32 addr);

int eamt_count(__u64 *count);
bool eamt_is_empty(void);
int eamt_foreach(int (*cb)(struct eamt_entry *, void *), void *arg,
		struct ipv4_prefix *offset);

#endif /* _JOOL_MOD_EAM_H */
