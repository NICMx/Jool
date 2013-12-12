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

	/** Should the entry never expire? */
	bool is_static;

	/** Session entries related to this BIB. */
	struct list_head sessions;
};


/**
 * Synchronizes the use of both BIB and Session.
 * This is global because:
 * - Locking of BIB and session needs to be performed outside of both of them (because we sometimes
 * decide whether or not to insert based on whether it's already on the table).
 * - The BIB and Session databases are inter-dependent (bib entries point to session entries and
 * vice-versa), which really makes a mess out of filtering if each has its own lock and the entries
 * are private.
 */
extern spinlock_t bib_session_lock;


/**
 * Initializes the three tables (UDP, TCP and ICMP).
 * Call during initialization for the remaining functions to work properly.
 */
int bib_init(void);

/**
 * Adds "entry" to the BIB table whose layer-4 protocol is "l4_proto".
 * Expects all fields from "entry" to have been initialized.
 *
 * Because never in this project is required otherwise, assumes the entry is not yet on the table.
 *
 * You must lock bib_session_lock before calling this function.
 *
 * @param entry row to be added to the table.
 * @param l4_proto identifier of the table to add "entry" to.
 * @return whether the entry could be inserted or not. It will not be inserted if some dynamic
 *		memory allocation failed.
 */
int bib_add(struct bib_entry *entry, l4_protocol l4_proto);

/**
 * Returns the BIB entry from the "l4_proto" table whose IPv4 side (address and port) is "address".
 *
 * You must lock bib_session_lock before calling this function.
 *
 * @param address address and port you want the BIB entry for.
 * @param l4_proto identifier of the table to retrieve the entry from.
 * @return the BIB entry from the "l4_proto" table whose IPv4 side (address and port) is "address".
 *		Returns NULL if there is no such entry.
 */
struct bib_entry *bib_get_by_ipv4(struct ipv4_tuple_address *address, l4_protocol l4_proto);
/**
 * Returns the BIB entry from the "l4_proto" table whose IPv6 side (address and port) is "address".
 *
 * You must lock bib_session_lock before calling this function.
 *
 * @param address address and port you want the BIB entry for.
 * @param l4_proto identifier of the table to retrieve the entry from.
 * @return the BIB entry from the "l4_proto" table whose IPv6 side (address and port) is "address".
 *		Returns NULL if there is no such entry.
 */
struct bib_entry *bib_get_by_ipv6(struct ipv6_tuple_address *address, l4_protocol l4_proto);
/**
 * Returns any BIB entry from the "l4_proto" table whose IPv6 address is "address".
 *
 * @param address address you want any BIB entry for.
 * @param l4_proto identifier of the table to retrieve the entry from.
 * @return some BIB entry from the "l4_proto" table whose IPv6 address is "address".
 */
struct bib_entry *bib_get_by_ipv6_only(struct in6_addr *address, l4_protocol l4_proto);

/**
 * Returns the BIB entry you'd expect from the "tuple" tuple.
 *
 * That is, when we're translating from IPv6 to IPv4, returns the BIB whose IPv6 address is
 * "tuple"'s source address.
 * When we're translating from IPv4 to IPv6, returns the BIB whose IPv4 address is "tuple"'s
 * destination address.
 *
 * @param tuple summary of the packet. Describes the BIB you need.
 * @return the BIB entry you'd expect from the "tuple" tuple.
 */
struct bib_entry *bib_get(struct tuple *tuple);

/**
 * Attempts to remove the "entry" entry from the BIB table whose protocol is "l4_proto".
 * Even though the entry is removed from the table, it is not kfreed.
 *
 * @param entry row to be removed from the table.
 * @param l4_proto identifier of the table to remove "entry" from.
 * @return whether the entry was in fact removed or not. The removal will fail if the entry is not
 *		on the table, or if it still has related session entries.
 */
bool bib_remove(struct bib_entry *entry, l4_protocol l4_proto);

/**
 * Empties the BIB tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void bib_destroy(void);

/**
 * Helper function, intended to initialize a BIB entry.
 * The entry is generated IN DYNAMIC MEMORY (if you end up not inserting it to a BIB table, you need
 * to kfree it).
 */
struct bib_entry *bib_create(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6,
		bool is_static);

/**
 * Asume que el candado ya se reservó.
 */
int bib_for_each(l4_protocol l4_proto, int (*func)(struct bib_entry *, void *), void *arg);

/**
 * Helper function, returns "true" if "bib_1" holds the same addresses and ports as "bib_2".
 *
 * @param bib_1 entry to compare to "bib_2".
 * @param bib_2 entry to compare to "bib_1".
 * @return whether "bib_1" and "bib_2" hold the same addresses and ports. Note, related session
 *		entries are not compared.
 */
bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2);


#endif /* _NF_NAT64_BIB_H */
