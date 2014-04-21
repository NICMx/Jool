#ifndef _NF_NAT64_BIB_H
#define _NF_NAT64_BIB_H

/**
 * @file
 * The Binding Information Bases.
 * Formally defined in RFC 6146 section 3.1.
 *
 * @author Alberto Leiva
 */

#include <linux/spinlock.h>
#include "nat64/comm/types.h"


/**
 * A row, intended to be part of one of the BIB tables.
 * A binding between a transport address from the IPv4 network to one from the IPv6 network.
 *
 * Please note that modifications to this structure may need to cascade to config_proto.h.
 */
struct bib_entry {
	/** The address from the IPv4 network. */
	struct ipv4_tuple_address ipv4;
	/** The address from the IPv6 network. */
	struct ipv6_tuple_address ipv6;

	/** l4 protocol used for pool4 return. */
	l4_protocol l4_proto;

	/**
	 * Should the entry never expire?
	 *
	 * This field is currently only being used by the userspace app's code. If you want to do
	 * something else with it, keep in mind that you might face the wrath of concurrence hell,
	 * because config.c's mutex is the only thing protecting it.
	 *
	 * The kernel never needs to know whether the entry is static. Preventing the death of a static
	 * entry when it runs out of sessions is handled by adding a fake user to refcounter.
	 */
	bool is_static;

	/**
	 * Number of active references to this entry, excluding the BIB database's. When this reaches
	 * zero, the entry is removed from the database and freed.
	 */
	struct kref refcounter;

	struct rb_node tree6_hook;
	struct rb_node tree4_hook;
};

/**
 * Initializes the kmem_cache for efficient allocation.
 * Call during initialization for the remaining functions to work properly.
 */
int bib_init(void);

/**
 * Empties the kmem_cache.
 * Call during destruction to avoid memory leaks.
 */
void bib_destroy(void);

/**
 * Helper function, intended to initialize a BIB entry.
 * The entry is generated IN DYNAMIC MEMORY (if you end up not inserting it to a BIB table, you need
 * to bib_kfree() it).
 */
struct bib_entry *bib_create(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6,
		bool is_static, l4_protocol l4_proto);

/**
 * Helper function, intended to increment a BIB refcounter
 */
void bib_get(struct bib_entry *bib);
/**
 * Helper function, intended to decrement a BIB refcounter
 */
int bib_return(struct bib_entry *bib);

/**
 * Warning: Careful with this one; "bib" cannot be NULL.
 */
void bib_kfree(struct bib_entry *bib);

#endif /* _NF_NAT64_BIB_H */
