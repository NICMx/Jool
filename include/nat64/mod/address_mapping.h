#ifndef _JOOL_MOD_ADDRESS_MAPPING_H
#define _JOOL_MOD_ADDRESS_MAPPING_H

/*
 * address_mapping.h
 *
 *  Created on: Nov 25, 2014
 *  @author: Daniel Hdz Felix
 */

#include "nat64/comm/types.h"

/**
 * Explicit Address Mapping definition.
 * Intended to be a row in the Explicit Address Mapping Table, bind an IPv4 Prefix to an IPv6 Prefix
 * and vice versa.
 */
struct eam_entry {
	/** The prefix address for the IPv4 network. */
	struct ipv4_prefix pref4;
	/** The prefix address for the IPv6 network. */
	struct ipv6_prefix pref6;
	/** Appends this entry to the database's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the database's IPv4 index. */
	struct rb_node tree4_hook;
};

/**
 *	Insert IPv6 Prefix "ip6_pref" and IPv4 Prefix "ip4_pref" to the database, return zero if the
 *	insert was successful.
 *
 *	If the "ipX_pref" contains or is part of a prefix indexed in the databases, then returns error.
 */
int address_mapping_insert_entry(struct ipv6_prefix *ip6_pref, struct ipv4_prefix *ip4_pref);

/**
 * Look in the IPv4 address mapping table, if the IPv4 address "addr" is part of a prefix indexed
 * in the table, if "addr" exists, append the mapped IPv6 prefix to "result" and also append the
 * suffix from "addr" to "result".
 *
 * otherwise return error.
 */
int address_mapping_get_ipv6_by_ipv4(struct in_addr *addr, struct in6_addr *result);

/**
 * Look in the IPv6 address mapping table, if the IPv6 address "addr6" is part of a prefix indexed
 * in the table, if "addr6" exists, append the mapped IPv4 prefix to "result" and also append the
 * suffix from "addr6" to "result".
 *
 * otherwise return error.
 */
int address_mapping_get_ipv4_by_ipv6(struct in6_addr *addr6, struct in_addr *result);


#endif /* _JOOL_MOD_ADDRESS_MAPPING_H */
