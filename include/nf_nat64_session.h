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
 * Returns the session entry you'd expect from the "tuple" tuple.
 *
 * That is, looks ups the session entry by both source and destination
 * addresses.
 *
 * @param tuple summary of the packet. Describes the session you need.
 * @return the session entry you'd expect from the "tuple" tuple.
 *		returns null if no entry could be found.
 */
struct session_entry *nat64_get_session_entry(struct nf_conntrack_tuple *tuple);

/**
 * Normally looks ups an entry, except it ignores "tuple"'s source port.
 * As there may be more than one such entry, it returns any of them.
 *
 * The name comes from the fact that this functionality serves no purpose other
 * than determining whether a packet should be allowed through or not.
 * Also, it's somewhat abbreviated. The RFC calls it "address independent
 * filtering".
 *
 * Only works while translating from IPv4 to IPv6. Behavior us undefined
 * otherwise.
 *
 * TODO
 *
 * @param tuple summary of the packet. Describes the session(s) you need.
 * @return a session entry with a source IPv4 transport address equal to the
 *		tuple's IPv4 destination transport address, and destination IPv4
 *		address equal to the tuple's source address. Returns null if no entry
 *		could be found.
 */
bool nat64_is_allowed_by_address_filtering(struct nf_conntrack_tuple *tuple);

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
