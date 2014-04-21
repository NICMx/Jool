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
#include "nat64/mod/bib.h"
#include "nat64/mod/packet.h"


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
 * Returns the BIB entry you'd expect from the "tuple" tuple.
 *
 * That is, when we're translating from IPv6 to IPv4, returns the BIB whose IPv6 address is
 * "tuple"'s source address.
 * When we're translating from IPv4 to IPv6, returns the BIB whose IPv4 address is "tuple"'s
 * destination address.
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
 * @param[in] address address and port you want the BIB entry for.
 * @param[in] l4_proto identifier of the table to retrieve the entry from.
 * @param[out] the BIB entry from the table will be placed here.
 * @return error status.
 */
int bibdb_get_by_ipv6(struct ipv6_tuple_address *addr, l4_protocol l4_proto,
		struct bib_entry **result);

/**
 * Adds "in_bib" to the BIB table whose layer-4 protocol is "l4_proto".
 * Expects all fields from "entry" to have been initialized.
 *
 * Because never in this project is required otherwise, assumes the entry is not yet on the table.
 *
 * If the "in_bib" is added to the table, "tree_bib" will point to "in_bib",
 * otherwise "tree_bib" will point to a session of the table.
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
 * Note, I *think* that the underlying data structure will go bananas if you attempt to remove an
 * entry that hasn't been previously inserted. I haven't double-checked this because all of the
 * current uses of this function validate before removing.
 *
 * @param entry row to be removed from the table.
 * @param l4_proto identifier of the table to remove "entry" from.
 * @return error status.
 */
int bibdb_remove(struct bib_entry *entry, l4_protocol l4_proto);

/**
 * Asume que el candado ya se reservó.
 */
int bibdb_for_each(l4_protocol l4_proto, int (*func)(struct bib_entry *, void *), void *arg);
int bibdb_for_each_ipv6(l4_protocol l4_proto, struct in6_addr *addr,
		int (*func)(struct bib_entry *, void *), void *arg);
int bibdb_allocate_ipv4_transport_address(struct tuple *base,
		struct ipv4_tuple_address *result);
int bibdb_count(l4_protocol proto, __u64 *result);

int bibdb_get_or_create_ipv6(struct fragment *frag, struct tuple *tuple, struct bib_entry **bib);

#endif /* _NF_NAT64_BIB_DB_H */
