#ifndef _NF_NAT64_BIB_DB_H
#define _NF_NAT64_BIB_DB_H

/**
 * @file
 * The Binding Information Bases.
 * Formally defined in RFC 6146 section 3.1.
 *
 * @author Alberto Leiva
 */

#include <linux/spinlock.h>
#include "nat64/comm/types.h"
#include "nat64/mod/packet.h"

/******************************** bib.h *************************************/


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

/**
 * Make sure you use bib_get or bibdb_get before you use
 * this function, otherwise could return a negative number
 * or an invalid number of sessions.
 */
int bib_session_counter(struct bib_entry *bib);


/************************* End of bib.h *************************************/

/**
 * Initializes the three tables (UDP, TCP and ICMP).
 * Call during initialization for the remaining functions to work properly.
 */
int bibdb_init(void);
/**
 * Empties the BIB tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void bibdb_destroy(void);

/**
 * Makes "result" point to the BIB entry you'd expect from the "tuple" tuple.
 *
 * That is, when we're translating from IPv6 to IPv4, "result" will point to the BIB whose IPv6
 * address is "tuple"'s source address.
 * When we're translating from IPv4 to IPv6, "result" will point to the BIB whose IPv4 address is
 * "tuple"'s destination address.
 *
 * It increases "result"'s refcount. Make sure you release it when you're done.
 *
 * @param[in] tuple summary of the packet. Describes the BIB you need.
 * @param[out] the BIB entry you'd expect from the "tuple" tuple.
 * @return error status.
 */
int bibdb_get(struct tuple *tuple, struct bib_entry **result);

/**
 * Makes "result" point to the BIB entry from the "l4_proto" table whose IPv4 side (address and
 * port) is "addr".
 *
 * It increases "result"'s refcount. Make sure you release it when you're done.
 *
 * @param[in] address address and port you want the BIB entry for.
 * @param[in] l4_proto identifier of the table to retrieve the entry from.
 * @param[out] the BIB entry from the table will be placed here.
 * @return error status.
 */
int bibdb_get_by_ipv4(struct ipv4_tuple_address *addr, l4_protocol l4_proto,
		struct bib_entry **result);
/**
 * Makes "result" point to the BIB entry from the "l4_proto" table whose IPv6 side (address and
 * port) is "addr".
 *
 * It increases "result"'s refcount. Make sure you release it when you're done.
 *
 * @param[in] address address and port you want the BIB entry for.
 * @param[in] l4_proto identifier of the table to retrieve the entry from.
 * @param[out] the BIB entry from the table will be placed here.
 * @return error status.
 */
int bibdb_get_by_ipv6(struct ipv6_tuple_address *addr, l4_protocol l4_proto,
		struct bib_entry **result);
/**
 * Makes "result" point to the BIB entry that corresponds to "tuple" (see bibdb_get()). If it
 * doesn't exist, it is created.
 *
 * It's sort of like calling bibdb_get_by_ipv6() and then bibdb_add() if it failed, except the
 * latter has concurrence issues.
 *
 * It increases "result"'s refcount. Make sure you release it when you're done.
 */
int bibdb_get_or_create_ipv6(struct fragment *frag, struct tuple *tuple, struct bib_entry **bib);

/**
 * Adds "in_bib" to the BIB table whose layer-4 protocol is "l4_proto".
 * Expects all fields from "entry" to have been initialized.
 *
 * Because never in this project is required otherwise, assumes the entry is not yet on the table.
 *
 * The table's references are not supposed to count towards the entries' refcounts. Do free your
 * reference if your entry made it into the table; do not assume you're transferring it.
 *
 * @param entry row to be added to the table.
 * @param l4_proto identifier of the table to add "entry" to.
 * @return whether the entry could be inserted or not. It will not be inserted if some dynamic
 *		memory allocation failed.
 */
int bibdb_add(struct bib_entry *entry, l4_protocol l4_proto);

/**
 * Attempts to remove the "entry" entry from the BIB table whose protocol is "l4_proto".
 * Even though the entry is removed from the table, it is not kfreed.
 *
 * @param entry row to be removed from the table.
 * @param l4_proto identifier of the table to remove "entry" from.
 * @return error status.
 */
int bibdb_remove(struct bib_entry *entry, l4_protocol l4_proto);

/**
 * Runs the "func" function for every entry in the table whose protocol is "l4_proto".
 *
 * @param l4_proto protocol of the table you want to iterate in.
 * @param func function you want to execute for every entry. Will receive both the entry and "arg"
 * 		as parameters. you can break iteration early by having this function return nonzero.
 * @param arg something you want to send func for every entry.
 */
int bibdb_for_each(l4_protocol l4_proto, int (*func)(struct bib_entry *, void *), void *arg);
/**
 * Sets in the value pointed by "result" the number of entries in the table whose protocol is
 * "l4_proto".
 */
int bibdb_count(l4_protocol proto, __u64 *result);


int bibdb_get_or_create_ipv6(struct fragment *frag, struct tuple *tuple, struct bib_entry **bib);
int bibdb_delete_by_ipv4(struct in_addr *addr);

int biddb_exists_on_addr(struct in_addr *addr);

#endif /* _NF_NAT64_BIB_DB_H */
