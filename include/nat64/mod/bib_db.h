#ifndef _NF_NAT64_BIB_DB_H
#define _NF_NAT64_BIB_DB_H

/**
 * @file
 * The Binding Information Bases.
 * Formally defined in RFC 6146 section 3.1.
 *
 * @author Alberto Leiva
 * @author Daniel Hernandez
 */

#include "nat64/comm/types.h"
#include "nat64/mod/packet.h"

/******************************** BIB Entries *************************************/


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
	 * Number of active references to this entry, excluding the ones from the table it belongs to.
	 * When this reaches zero, the entry is removed from the table and freed.
	 */
	struct kref refcounter;

	/** Appends this entry to the database's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the database's IPv4 index. */
	struct rb_node tree4_hook;
};

/**
 * Allocates and initializes a BIB entry.
 * The entry is generated in dynamic memory; remember to kfree, return or pass it along.
 */
struct bib_entry *bib_create(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6,
		bool is_static, l4_protocol l4_proto);
/**
 * Roughly reverts the work of bib_create() by freeing "bib" from memory. What breaks the symmetry
 * is the return of "bib"'s IPv4 address to the IPv4 pool (the borrow doesn't happen in
 * bib_create()).
 *
 * This is intended to be used when you are the only user of "bib" (i.e. you just created it
 * and you haven't inserted it to any tables). If that might not be the case, use bib_return()
 * instead.
 */
void bib_kfree(struct bib_entry *bib);

/**
 * Marks "bib" as being used by the caller. The idea is to prevent the cleaners from deleting it
 * while it's being used.
 *
 * You have to grab one of these references whenever you gain access to an entry. Keep in mind that
 * the bib* and bibdb* functions might have already done that for you. Session entries referencing
 * BIB entries must also count.
 *
 * Remove the mark when you're done by calling bib_return().
 */
void bib_get(struct bib_entry *bib);
/**
 * Reverts the work of bib_get() by removing the mark.
 *
 * If no other references to "bib" exist, this function will take care of removing and freeing it.
 *
 * DON'T USE "bib" AFTER YOU RETURN IT!
 */
int bib_return(struct bib_entry *bib);
/**
 * If for some reason you locked the BIB tables and need to return a BIB entry, you have to use
 * this version so the return doesn't try to lock the table again.
 */
int bib_return_lockless(struct bib_entry *bib);


/************************* BIB (The database) *************************************/

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
 * It increases "result"'s refcount. Make sure you decrement it when you're done.
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
 * It increases "result"'s refcount. Make sure you decrement it when you're done.
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
 * Adds "entry" to the BIB table it belongs. Make sure you initialized "entry" using bib_create(),
 * please.
 *
 * The table's references are not supposed to count towards the entries' refcounts. Do free your
 * reference if your entry made it into the table; do not assume you're transferring it.
 *
 * @param entry row to be added to the table.
 * @param l4_proto identifier of the table to add "entry" to.
 * @return whether the entry could be inserted or not. It will not be inserted if some dynamic
 *		memory allocation failed.
 */
int bibdb_add(struct bib_entry *entry);

/**
 * Attempts to remove the "entry" entry from its BIB. It doesn't kfree "entry".
 *
 * @param entry row to be removed from the table.
 * @param lock send true if this function should lock the table before removing. Send false if you
 * 		already locked it.
 * @return error status.
 */
int bibdb_remove(struct bib_entry *entry, bool lock);

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
 * Similar to bibdb_for_each(), except it only runs the function for BIB entries whose IPv4
 * transport address is "addr".
 */
int bibdb_iterate_by_ipv4(l4_protocol l4_proto, struct ipv4_tuple_address *ipv4, bool starting,
		int (*func)(struct bib_entry *, void *), void *arg);
/**
 * Sets in the value pointed by "result" the number of entries in the database whose protocol is
 * "l4_proto".
 */
int bibdb_count(l4_protocol proto, __u64 *result);

/**
 * Returns in "bib" the BIB entry you'd expect from the "tuple" tuple.
 * If it doesn't exist, it is created, added and returned.
 * IPv6 to IPv4 direction.
 */
int bibdb_get_or_create_ipv6(struct fragment *frag, struct tuple *tuple, struct bib_entry **bib);

/**
 * Removes the fake users of all the BIB entries whose local IPv4 address is "addr4".
 * This is probably a lot faster than you think.
 */
int bibdb_delete_by_ipv4(struct in_addr *addr);


#endif /* _NF_NAT64_BIB_DB_H */
