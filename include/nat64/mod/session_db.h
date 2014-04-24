#ifndef _NF_NAT64_SESSION_DB_H
#define _NF_NAT64_SESSION_DB_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 *
 * @author Alberto Leiva
 */

#include "nat64/comm/types.h"
#include "nat64/mod/session.h"
#include "nat64/mod/bib.h"

typedef enum timer_type {
	TIMERTYPE_UDP = 0,
	TIMERTYPE_TCP_EST = 1,
	TIMERTYPE_TCP_TRANS = 2,
	TIMERTYPE_TCP_SYN = 3,
	TIMERTYPE_ICMP = 4,
#define TIMER_TYPE_COUNT 5
} timer_type;

/**
 * Initializes the three tables (UDP, TCP and ICMP).
 * Call during initialization for the remaining functions to work properly.
 */
int sessiondb_init(void);
/**
 * Empties the session tables, freeing any memory being used by them.
 * Call during destruction to avoid memory leaks.
 */
void sessiondb_destroy(void);


/**
 * Returns in "result" the session entry from the "l4_proto" table whose IPv4 side (both addresses
 * and ports) is "pair".
 *
 * @param[in] pairt IPv4 data you want the session entry for.
 * @param[in] l4_proto identifier of the table to retrieve the entry from.
 * @param[out] result the Session entry from the "l4_proto" table whose IPv4 side (both addresses
 *		and ports) is "address".
 * @return error status.
 */
int sessiondb_get_by_ipv4(struct ipv4_pair *pair, l4_protocol l4_proto,
		struct session_entry **result);
/**
 * Returns in "result" the session entry from the "l4_proto" table whose IPv6 side (both addresses
 * and ports) is "pair".
 *
 * @param[in] pairt IPv6 data you want the session entry for.
 * @param[in] l4_proto identifier of the table to retrieve the entry from.
 * @param[out] result the Session entry from the "l4_proto" table whose IPv6 side (both addresses
 *		and ports) is "address".
 * @return error status.
 */
int sessiondb_get_by_ipv6(struct ipv6_pair *pair, l4_protocol l4_proto,
		struct session_entry **result);
/**
 * Returns in "result" the session entry you'd expect from the "tuple" tuple.
 *
 * That is, looks ups the session entry by both source and destination addresses.
 *
 * @param[in] tuple summary of the packet. Describes the session you need.
 * @param[out] result the session entry you'd expect from the "tuple" tuple.
 * @return error status.
 */
int sessiondb_get(struct tuple *tuple, struct session_entry **result);

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
bool sessiondb_allow(struct tuple *tuple);

/**
 * Adds "in_session" to the session table whose layer-4 protocol is "entry->l4_proto".
 * Expects all fields but the list_heads from "entry" to have been initialized.
 *
 * if the in_session is added to the table, "tree_session" will point to "in_session",
 * otherwise "tree_session" will point to a session of the table.
 *
 * @param entry row to be added to the table.
 * @return whether the entry could be inserted or not. It will not be inserted
 *		if some dynamic memory allocation failed.
 */
int sessiondb_add(struct session_entry *session);

int sessiondb_for_each(l4_protocol l4_proto, int (*func)(struct session_entry *, void *), void *arg);
int sessiondb_count(l4_protocol proto, __u64 *result);

/**
 * this functions is used in statics_routes to delete every session of the bib
 */
int sessiondb_delete_by_bib(struct bib_entry *bib);

int sessiondb_get_or_create_ipv6(struct tuple *tuple, struct bib_entry *bib, struct session_entry **session);
int sessiondb_get_or_create_ipv4(struct tuple *tuple, struct bib_entry *bib, struct session_entry **session);

/**
 * Helper of the set_*_timer functions. Safely updates "session"->dying_time and moves it from its
 * original location to the end of "list".
 */
void sessiondb_update_timer(struct session_entry *session, timer_type type, __u64 ttl);

#endif /* _NF_NAT64_SESSION_DB_H */
