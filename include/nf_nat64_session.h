#ifndef _NF_NAT64_SESSION_H
#define _NF_NAT64_SESSION_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 */

#include "nf_nat64_types.h"
#include "nf_nat64_bib.h"

/**
 * A row, intended to be part of one of the session tables.
 * The mapping between the connections, as perceived by both sides (IPv4 vs
 * IPv6).
 */
struct session_entry
{
	/** IPv6 version of the connection. */
	struct ipv6_pair ipv6;
	/** IPv4 version of the connection. */
	struct ipv4_pair ipv4;

	/** Should the session never expire? */
	bool is_static;
	/**
	 * Millisecond (from the epoch) this session should expire in,
	 * if still inactive.
	 */
	unsigned int dying_time;

	/**
	 * Owner bib of this session. Used for quick access during removal.
	 * (when the session dies, the BIB might have to die too.)
	 */
	struct bib_entry *bib;
	/**
	 * Chains this session with the rest from the same BIB (see
	 * bib_entry.session_entries).
	 * Used by the BIB to know whether it should commit suicide or not.
	 */
	struct list_head entries_from_bib;
	/**
	 * Chains this session with the rest (see all_sessions, defined in
	 * nf_nat_session.h).
	 * Used for iterating while looking for expired sessions.
	 */
	struct list_head all_sessions;
	/**
	 * Transport protocol of the table this entry is in.
	 * Used to know which table the session should be removed from when
	 * expired.
	 */
	int l4protocol;
};

/**
 * Initializes the three tables (UDP, TCP and ICMP).
 * Call during initialization for the remaining functions to work properly.
 */
void nat64_session_init(void);

/**
 * Adds "entry" to the session table whose layer-4 protocol is
 * "entry->protocol".
 * Expects all fields but the list_heads from "entry" to have been initialized.
 *
 * Because never in this project is required otherwise, assumes the entry
 * is not yet on the table.
 *
 * @param entry row to be added to the table.
 * @return whether the entry could be inserted or not. It will not be inserted
 *		if some dynamic memory allocation failed.
 */
bool nat64_add_session_entry(struct session_entry *entry);

/**
 * Returns the session entry (from the table whose layer-4 protocol is
 * "l4protocol") whose IPv4 addresses are "remote" and "local".
 *
 * @param remote address of the IPv4 network's remote machine.
 * @param local address from the IPv4 end of the NAT64.
 * @param l4protocol identifier of the table to retrieve "entry" from. Should
 * 		be either IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return entry (from the table whose layer-4 protocol is "l4protocol") whose
 *		IPv4 addresses are "remote" and "local".
 */
struct session_entry *nat64_get_session_entry_by_ipv4(struct ipv4_tuple_address *remote,
		struct ipv4_tuple_address *local, int l4protocol);
/**
 * Returns the session entry (from the table whose layer-4 protocol is
 * "l4protocol") whose IPv6 addresses are "remote" and "local".
 *
 * @param local IPv6 version of the address of the IPv4 network's remote node.
 * @param remote address of the IPv6 network's remote machine.
 * @param l4protocol identifier of the table to retrieve "entry" from. Should
 * 		be either IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP from linux/in.h.
 * @return entry (from the table whose layer-4 protocol is "l4protocol") whose
 *		IPv6 addresses are "remote" and "local".
 */
struct session_entry* nat64_get_session_entry_by_ipv6(struct ipv6_tuple_address *local,
		struct ipv6_tuple_address *remote, int l4protocol);

/**
 * Set "entry"'s time to live as <current time> + "ttl".
 *
 * @param entry session entry to update.
 * @param ttl number of milliseconds "entry" should survive if inactive.
 */
void nat64_update_session_lifetime(struct session_entry *entry, unsigned int ttl);

/**
 * Destroys the session table's reference to "entry". It does NOT kfree "entry".
 * Also, it removes "entry" regardless of whether it is static or not.
 *
 * @param entry entry to be removed from its table.
 * @return "true" if "entry" was in fact in the table. "false" if it wasn't,
 *		and hence it wasn't removed from anywhere.
 */
bool nat64_remove_session_entry(struct session_entry *entry);

/**
 * Removes from the tables the entries whose lifetime has expired. The entries
 * are also freed from memory.
 */
void nat64_clean_old_sessions(void);

/**
 * Empties the session tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void nat64_session_destroy(void);

/**
 * Helper function, returns "true" if "bib_1" holds the same protocol,
 * addresses and ports as "bib_2".
 *
 * @param bib_1 entry to compare to "bib_2".
 * @param bib_2 entry to compare to "bib_1".
 * @return whether "bib_1" and "bib_2" hold the same protocol, addresses and
 *		ports.
 */
bool session_entry_equals(struct session_entry *session_1, struct session_entry *session_2);

#endif
