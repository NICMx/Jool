#ifndef _NF_NAT64_BIB_H
#define _NF_NAT64_BIB_H

/**
 * @file
 * The Binding Information Bases.
 * Formally defined in RFC 6146 section 3.1.
 *
 * @author Alberto Leiva
 */

#include <linux/types.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include "nat64/types.h"


/**
 * A row, intended to be part of one of the BIB tables.
 * A binding between a transport address from the IPv4 network to one from the IPv6 network.
 *
 * Please note that modifications to this structure may need to cascade to *_module_comm.h.
 */
struct bib_entry
{
	/** The address from the IPv4 network. */
	struct ipv4_tuple_address ipv4;
	/** The address from the IPv6 network. */
	struct ipv6_tuple_address ipv6;

	/** Session entries related to this BIB. */
	struct list_head session_entries;
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
bool nat64_bib_init(void);

/**
 * Adds "entry" to the BIB table whose layer-4 protocol is "protocol".
 * Expects all fields from "entry" to have been initialized.
 * 
 * Because never in this project is required otherwise, assumes the entry is not yet on the table.
 *
 * @param entry row to be added to the table.
 * @param protocol identifier of the table to add "entry" to. Should be either IPPROTO_UDP,
 *		IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return whether the entry could be inserted or not. It will not be inserted if some dynamic
 *		memory allocation failed.
 */
bool nat64_add_bib_entry(struct bib_entry *entry, u_int8_t l4protocol);

/**
 * Returns the BIB entry from the "l4protocol" table whose IPv4 side (address and port) is
 * "address".
 *
 * @param address address and port you want the BIB entry for.
 * @param l4protocol identifier of the table to retrieve the entry from. Should be either
 *		IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return the BIB entry from the "l4protocol" table whose IPv4 side (address and port) is
 *		"address". Returns NULL if there is no such an entry.
 */
struct bib_entry *nat64_get_bib_entry_by_ipv4(struct ipv4_tuple_address *address,
		u_int8_t l4protocol);
/**
 * Returns the BIB entry from the "l4protocol" table whose IPv6 side (address and port) is
 * "address".
 *
 * @param address address and port you want the BIB entry for.
 * @param l4protocol identifier of the table to retrieve the entry from. Should be either
 *		IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMPV6 from linux/in.h.
 * @return the BIB entry from the "l4protocol" table whose IPv6 side (address and port) is
 *		"address". Returns NULL if there is no such an entry.
 */
struct bib_entry *nat64_get_bib_entry_by_ipv6(struct ipv6_tuple_address *address,
		u_int8_t l4protocol);
struct bib_entry *nat64_get_bib_entry_by_ipv6_only(struct in6_addr *address, u_int8_t l4protocol);

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
struct bib_entry *nat64_get_bib_entry(struct nf_conntrack_tuple *tuple);

/**
 * Attempts to remove the "entry" entry from the BIB table whose protocol is "l4protocol".
 * Even though the entry is removed from the table, it is not kfreed.
 *
 * @param entry row to be removed from the table.
 * @param l4protocol identifier of the table to remove "entry" from. Should be either IPPROTO_UDP,
 *		IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return whether the entry was in fact removed or not. The removal will fail if the entry is not
 *		on the table, or if it still has related session entries.
 */
bool nat64_remove_bib_entry(struct bib_entry *entry, u_int8_t l4protocol);

/**
 * Empties the BIB tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void nat64_bib_destroy(void);

/**
 * Helper function, intended to initialize a BIB entry.
 * The entry is generated IN DYNAMIC MEMORY (if you end up not inserting it to a BIB table, you need
 * to kfree it).
 */
struct bib_entry *nat64_create_bib_entry(struct ipv4_tuple_address *ipv4,
		struct ipv6_tuple_address *ipv6);

/**
 * Creates an array out of the "l4protocol" BIB's data and places it in *"array".
 *
 * @param l4protocol identifier of the table to array-ize. Should be either IPPROTO_UDP, IPPROTO_TCP
 *		or IPPROTO_ICMP from linux/in.h.
 * @param array the result will be stored here. Yes, this parameter is a horrible abomination. Think
 *		of it this way: It's an array (asterisk 2) of pointers (asterisk 3). The remaining asterisk
 *		makes it a by-reference argument. FML.
 * @return the resulting length of "array". May be -1, if memory could not be allocated.
 *
 * You have to kfree "array" after you use it. Don't kfree its contents, as they are references to
 * the real entries from the table.
 */
__s32 nat64_bib_to_array(__u8 l4protocol, struct bib_entry ***array);

/**
 * Helper function, returns "true" if "bib_1" holds the same addresses and ports as "bib_2".
 *
 * @param bib_1 entry to compare to "bib_2".
 * @param bib_2 entry to compare to "bib_1".
 * @return whether "bib_1" and "bib_2" hold the same addresses and ports. Note, related session
 *		entries are not compared.
 */
bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2);

#endif
