#ifndef _JOOL_MOD_HOST6_NODE_H
#define _JOOL_MOD_HOST6_NODE_H

/**
 * @file
 * This is an additional index for BIB. Think of it as a private class of BIB.
 *
 * For every IPv6 node, it remembers all the IPv4 addresses currently being used to mask it,
 * so Jool doesn't have to iterate over all the node's BIB entries whenever it needs this info.
 *
 * This is because Jool tries hard to always mask nodes with the same address. When this cannot
 * be ensured, most likely the node will have lots of BIB entries, and most of them will have the
 * same IPv4 address, so iterating over its entire BIB entry space would be very slow.
 *
 * Note: Use all this functions here to manipulate the objects described in here, all this functions
 * are intended to be thread safe.
 */

#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/bib_db.h"

/**
 * A row, intended to be a Host on the IPv6 network, that keeps references of the IPv4 borrowed
 * from the pool4 (only in the layer-3 protocol).
 */
struct host6_node {
	/** The layer-3 identifier of the host that starts the communication through Jool. */
	struct in6_addr ipv6_addr;
	/** The IPv4 addresses that are assigned to this IPv6 Host by Jool. */
	struct list_head ipv4_addr;
	/** A hook for the host6_table. */
	struct rb_node tree_hook;
	/**
	 * Number of active references to this entry,
	 * When this reaches zero, the entry is removed from the table and freed.
	 */
	struct kref refcounter;
};

/**
 * An entry that holds a copy of the in_addr borrowed from pool4.
 */
struct host_addr4 {
	/** The layer-3 identifier. */
	struct in_addr addr;
	/**	A reference for its Host6_node. */
	struct host6_node *node6;
	/**
	 * Number of active references to this entry,
	 * When this reaches zero, the entry is removed from the ipv6_node and freed.
	 */
	struct kref refcounter;
	/** The hook for where this IPv4 address is hooked. */
	struct list_head list_hook;
};

/**
 * Marks "node6" as being used by the caller. The idea is to prevent the cleaners from deleting it
 * while it's being used.
 *
 * You have to grab one of these references whenever you gain access to an entry. Keep in mind that
 * the host6_node* functions might have already done that for you. .
 *
 * Remove the mark when you're done by calling host6_node_return().
 */
void host6_node_get(struct host6_node *node6);
/**
 * Reverts the work of host6_node_get() by removing the mark.
 *
 * If no other references to "node6" exist, this function will take care of removing and freeing it.
 *
 * DON'T USE "node6" AFTER YOU RETURN IT! (unless you know there's other active reference)
 */
int host6_node_return(struct host6_node *node6);

/**
 * Reverts the work of host_addr4_get() by removing the mark.
 *
 * If no other references to "addr4" exist, this function will take care of removing and freeing it.
 *
 * DON'T USE "addr4" AFTER YOU RETURN IT! (unless you know there's other active reference)
 */
int host_addr4_return(struct host_addr4 *addr4);

/**
 * Makes "result" point to the Host6_node entry that corresponds to "addr". If it
 * doesn't exist, it is created.
 *
 * It increases "result"'s refcount. Make sure you release it when you're done.
 */
int host6_node_get_or_create(struct in6_addr *addr, struct host6_node **result);

/**
 * Runs the "func" function for every in_addr in the host6_node.
 *
 * @param node host6_node you want to iterate in.
 * @param func function you want to execute for every entry. Will receive both the in_addr and "arg"
 * 		as parameters. you can break iteration early by having this function return nonzero.
 * @param arg something you want to send func for every entry.
 */
int host6_node_for_each_addr4(struct host6_node *node,
		int (*func)(struct in_addr *, void *), void *arg);

/**
 * Increment the reference of host_addr4 in "node" give it by the in_addr in bib->ipv4.l3, and
 * bib get a reference, if such reference doesn't exist in "node" then a host_addr4 will be
 * created, and added to IPv4's list of "node", bib get a reference to host_addr4.
 *
 * It is important that this function is called when the bib_entry it's being created, if this
 * function fail, the bib_entry needs be removed or destroyed.
 *
 * @param node the Host6_node which keeps the list of ipv4 addresses.
 *
 * @param bib The BIB entry that will get the reference of host_addr4.
 */
int host6_node_add_or_increment_addr4(struct host6_node *node, struct bib_entry *bib);

/**
 * Initializes the host6 database.
 * Call during initialization for the remaining functions to work properly.
 */
int host6_node_init(void);

/**
 * Empties the database, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void host6_node_destroy(void);

#endif /* _JOOL_MOD_HOST6_NODE_H */
