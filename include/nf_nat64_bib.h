#ifndef _NF_NAT64_BIB_H
#define _NF_NAT64_BIB_H

/**
 * @file
 * The Binding Information Bases.
 * Formally defined in RFC 6146 section 3.1.
 */

#include "nf_nat64_types.h"

/**
 * A row, intended to be part of one of the BIB tables.
 * A binding between a transport address from the IPv4 network to one from the
 * IPv6 network.
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
 * Initializes the three tables (UDP, TCP and ICMP).
 * Call during initialization for the remaining functions to work properly.
 */
void nat64_bib_init(void);

/**
 * Adds "entry" to the BIB table whose layer-4 protocol is "protocol".
 * Expects all fields from "entry" to have been initialized.
 * 
 * Because never in this project is required otherwise, assumes the entry
 * is not yet on the table.
 *
 * @param entry row to be added to the table.
 * @param protocol identifier of the table to add "entry" to. Should be either
 * 		IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return whether the entry could be inserted or not. It will not be inserted
 *		if some dynamic memory allocation failed.
 */
bool nat64_add_bib_entry(struct bib_entry *entry, int l4protocol);

/**
 * Returns the BIB entry (from the table whose layer-4 protocol is
 * "l4protocol") whose IPv4 address is "addr".
 *
 * @param addr IPv4 address and port of the BIB entry you want.
 * @param l4protocol identifier of the table to retrieve "entry" from. Should
 * 		be either IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return entry (from the table whose layer-4 protocol is "l4protocol") whose
 * 		IPv4 address is "addr".
 */
struct bib_entry* nat64_get_bib_entry_by_ipv4_addr(struct ipv4_tuple_address *addr, int l4protocol);

/**
 * Returns the BIB entry (from the table whose layer-4 protocol is
 * "l4protocol") whose IPv6 address is "addr".
 *
 * @param addr IPv6 address and port of the BIB entry you want.
 * @param l4protocol identifier of the table to retrieve "entry" from. Should
 * 		be either IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return entry (from the table whose layer-4 protocol is "l4protocol") whose
 * 		IPv6 address is "addr".
 */
struct bib_entry* nat64_get_bib_entry_by_ipv6_addr(struct ipv6_tuple_address *addr, int l4protocol);

/**
 * Attempts to remove the "entry" entry from the BIB table whose protocol is
 * "l4protocol".
 * Even though the entry is removed from the table, it is not kfreed.
 *
 * @param entry row to be removed from the table.
 * @param l4protocol identifier of the table to remove "entry" from. Should be
 * 		either IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return whether the entry was in fact removed or not. The removal will fail
 * 		if the entry is not on the table, or if it still has related session
 * 		entries.
 */
bool nat64_remove_bib_entry(struct bib_entry *entry, int l4protocol);

/**
 * Empties the BIB tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void nat64_bib_destroy(void);

/**
 * Helper function, intended to initialize a BIB entry.
 * The entry is generated IN DYNAMIC MEMORY (if you end up not inserting it to
 * a BIB table, you need to kfree it).
 */
struct bib_entry *nat64_create_bib_entry(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6);

/**
 * Helper function, returns "true" if "bib_1" holds the same addresses and
 * ports as "bib_2".
 *
 * @param bib_1 entry to compare to "bib_2".
 * @param bib_2 entry to compare to "bib_1".
 * @return whether "bib_1" and "bib_2" hold the same addresses and ports.
 * 		Note, related session entries are not compared.
 */
bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2);

#endif
