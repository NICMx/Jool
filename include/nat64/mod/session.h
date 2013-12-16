#ifndef _NF_NAT64_SESSION_H
#define _NF_NAT64_SESSION_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 *
 * @author Alberto Leiva
 */

#include "nat64/comm/types.h"
#include "nat64/mod/bib.h"


/**
 * A row, intended to be part of one of the session tables.
 * The mapping between the connections, as perceived by both sides (IPv4 vs IPv6).
 *
 * Please note that modifications to this structure may need to cascade to config_proto.h.
 */
struct session_entry {
	/** IPv6 version of the connection. */
	struct ipv6_pair ipv6;
	/** IPv4 version of the connection. */
	struct ipv4_pair ipv4;

	/** Jiffy (from the epoch) this session should expire in, if still inactive. */
	unsigned long dying_time;

	/**
	 * Owner bib of this session. Used for quick access during removal.
	 * (when the session dies, the BIB might have to die too.)
	 */
	struct bib_entry *bib;
	/**
	 * Chains this session with the rest from the same BIB (see bib_entry.session_entries).
	 * Used by the BIB to know whether it should commit suicide or not.
	 */
	struct list_head bib_list_hook;
	/**
	 * Chainer to one of the expiration timer lists (sessions_udp, sessions_tcp_est, etc).
	 * Used for iterating while looking for expired sessions.
	 */
	struct list_head expire_list_hook;
	/**
	 * Transport protocol of the table this entry is in.
	 * Used to know which table the session should be removed from when expired.
	 */
	l4_protocol l4_proto;

	/** Current TCP state.
	 * 	Each STE represents a state machine
	 */
	u_int8_t state;
};


/**
 * Initializes the three tables (UDP, TCP and ICMP).
 * Call during initialization for the remaining functions to work properly.
 */
int session_init(void);
/**
 * Empties the session tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void session_destroy(void);

/**
 * Adds "entry" to the session table whose layer-4 protocol is "entry->protocol".
 * Expects all fields but the list_heads from "entry" to have been initialized.
 *
 * Because never in this project is required otherwise, assumes the entry is not yet on the table.
 *
 * @param entry row to be added to the table.
 * @return whether the entry could be inserted or not. It will not be inserted
 *		if some dynamic memory allocation failed.
 */
int session_add(struct session_entry *entry);

/**
 * Returns the Session entry from the "l4protocol" table whose IPv4 side (both addresses and ports)
 * is "pair".
 *
 * @param pairt IPv4 data you want the Session entry for.
 * @param l4protocol identifier of the table to retrieve the entry from.
 * @return the Session entry from the "l4protocol" table whose IPv4 side (both addresses and posts)
 *		is "address". Returns NULL if there is no such an entry.
 */
struct session_entry *session_get_by_ipv4(struct ipv4_pair *pair, l4_protocol l4_proto);
/**
 * Returns the Session entry from the "l4protocol" table whose IPv6 side (both addresses and ports)
 * is "pair".
 *
 * @param pairt IPv6 data you want the Session entry for.
 * @param l4protocol identifier of the table to retrieve the entry from.
 * @return the Session entry from the "l4protocol" table whose IPv6 side (both addresses and posts)
 *		is "address". Returns NULL if there is no such an entry.
 */
struct session_entry *session_get_by_ipv6(struct ipv6_pair *pair, l4_protocol l4_proto);

/**
 * Returns the session entry you'd expect from the "tuple" tuple.
 *
 * That is, looks ups the session entry by both source and destination addresses.
 *
 * @param tuple summary of the packet. Describes the session you need.
 * @return the session entry you'd expect from the "tuple" tuple.
 *		returns null if no entry could be found.
 */
struct session_entry *session_get(struct tuple *tuple);

/**
 * Normally looks ups an entry, except it ignores "tuple"'s source port.
 * Returns "true" if such an entry could be found, "false" otherwise.
 *
 * The name comes from the fact that this functionality serves no purpose other than determining
 * whether a packet should be allowed through or not. The RFC calls it "address dependent
 * filtering".
 *
 * Only works while translating from IPv4 to IPv6. Behavior is undefined otherwise.
 *
 * @param tuple summary of the packet. Describes the session(s) you need.
 * @return whether there's a session entry with a source IPv4 transport address equal to the tuple's
 *		IPv4 destination transport address, and destination IPv4 address equal to the tuple's source
 *		address.
 */
bool session_allow(struct tuple *tuple);

/**
 * Destroys the session table's reference to "entry". It does NOT kfree "entry".
 * Also, it removes "entry" regardless of whether it is static or not.
 *
 * @param entry entry to be removed from its table.
 * @return "true" if "entry" was in fact in the table. "false" if it wasn't,
 *		and hence it wasn't removed from anywhere.
 */
bool session_remove(struct session_entry *entry);

int session_for_each(l4_protocol l4_proto, int (*func)(struct session_entry *, void *), void *arg);
int session_count(l4_protocol proto, __u64 *result);

/**
 * Helper function, intended to initialize a Session entry.
 * The entry is generated IN DYNAMIC MEMORY (if you end up not inserting it to a Session table, you
 * need to kfree it).
 */
struct session_entry *session_create(struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
		l4_protocol l4_proto);
/**
 * Helper function, returns "true" if "bib_1" holds the same protocol, addresses and ports as
 * "bib_2".
 *
 * @param bib_1 entry to compare to "bib_2".
 * @param bib_2 entry to compare to "bib_1".
 * @return whether "bib_1" and "bib_2" hold the same protocol, addresses and ports.
 */
bool session_entry_equals(struct session_entry *session_1, struct session_entry *session_2);

#endif /* _NF_NAT64_SESSION_H */
