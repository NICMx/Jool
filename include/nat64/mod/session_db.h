#ifndef _JOOL_MOD_SESSION_DB_H
#define _JOOL_MOD_SESSION_DB_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 *
 * Note: "Session database" is not the same as "session table"; the database consists of 3 tables.
 * Keep that in mind while you read comments.
 *
 * @author Alberto Leiva
 * @author Daniel Hernandez
 */

#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/comm/session.h"
#include "nat64/mod/bib_db.h"

/************************************* Session Entries **********************************/

/**
 * A timer which will delete expired sessions every once in a while.
 * All of the timer's sessions have the same time to live.
 *
 * Why not a single timer which takes care of all the sessions? Some reasons I remember:
 * - When the user updates timeouts, this makes updating existing sessions a O(1) operation (since
 *   the timer holds the timeout, not the sessions).
 * - It makes timer rescheduling trivial (sessions are sorted by expiration date, so new sessions
 *   are always simply added to the end of the list (O(1)) and knowing when the timer should be
 *   triggered next is a matter of peeking the first element (also O(1)).
 * - I seem to recall it takes care of some sync concern, but I can't remember what it was.
 *
 * Why not a timer per session? Well I don't know, it sounds like a lot of stress to the kernel
 * since we expect lots and lots of sessions.
 */
struct expire_timer {
	/** The actual timer. */
	struct timer_list timer;
	/** The sessions this timer is supposed to delete. Sorted by expiration time. */
	struct list_head sessions;
	/** All the sessions from the list above belong to this table (the reverse might not apply). */
	struct session_table *table;
	/**
	 * Offset from the "config" structure where the expiration time of this timer can be found.
	 * Except if this timer is "timer_syn", since the timeout of that one is constant.
	 */
	size_t timeout_offset;

	char *name;
};

/**
 * A row, intended to be part of one of the session tables.
 * The mapping between the connections, as perceived by both sides (IPv4 vs IPv6).
 *
 * Please note that modifications to this structure may need to cascade to
 * "struct session_entry_usr".
 *
 * TODO (performance) this structure is somewhat big (probably 128+ bytes) and there will be lots
 * of sessions in memory. Maybe turn l4_proto into a single-byte integer and remove some of the
 * transport addresses (since they can be extracted from bib).
 */
struct session_entry {
	/**
	 * IPv6 version of the connection.
	 *
	 * The RFC always calls the remote IPv6 node's address the "Source" IPv6 address.
	 * The prefix-based NAT64 address is always the "Destination" address.
	 * That is regardless of translation direction, which looks awful in the IPv4-to-IPv6 pipeline.
	 * We've decided to rename the "Source" address the "Remote" address. The "Destination" address
	 * is here the "Local" address.
	 * "Local" and "Remote" as in, from the NAT64's perspective.
	 */
	const struct ipv6_pair ipv6;
	/**
	 * IPv4 version of the connection.
	 *
	 * The RFC always calls the remote IPv4 node's address the "Destination" IPv4 address.
	 * The pool NAT64 address is always the "Source" address.
	 * That is regardless of translation direction, which looks awful in the IPv4-to-IPv6 pipeline.
	 * We've decided to rename the "Source" address the "Local" address. The "Destination" address
	 * is here the "Remote" address.
	 * "Local" and "Remote" as in, from the NAT64's perspective.
	 */
	const struct ipv4_pair ipv4;

	/** Jiffy (from the epoch) this session was last updated/used. */
	unsigned long update_time;

	/**
	 * Owner bib of this session. Used for quick access during removal.
	 * (when the session dies, the BIB might have to die too.)
	 */
	struct bib_entry *const bib;

	/**
	 * Number of active references to this entry, including the ones from the table it belongs to.
	 * When this reaches zero, the entry is released from memory.
	 */
	struct kref refcounter;
	/**
	 * Chainer to one of the expiration timer lists (sessions_udp, sessions_tcp_est, etc).
	 * Used for iterating while looking for expired sessions.
	 */
	struct list_head expire_list_hook;
	/**
	 * Expiration timer who is supposed to delete this session when its death time is reached.
	 */
	struct expire_timer *expirer;
	/**
	 * Transport protocol of the table this entry is in.
	 * Used to know which table the session should be removed from when expired.
	 */
	const l4_protocol l4_proto;

	/** Current TCP state. Only relevant if l4_proto == L4PROTO_TCP. */
	u_int8_t state;

	/** Appends this entry to the database's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the database's IPv4 index. */
	struct rb_node tree4_hook;
};

/**
 * Allocates and initializes a session entry.
 *
 * The entry is generated in dynamic memory; remember to session_return() it or pass it along.
 */
struct session_entry *session_create(struct ipv4_pair *ipv4, struct ipv6_pair *ipv6,
		l4_protocol l4_proto, struct bib_entry *bib);

/**
 * Creates a copy of session entry.
 *
 * The copy will not be part of the database regardless of session's state.
 */
struct session_entry *session_clone(struct session_entry *session);

/**
 * Marks "session" as being used by the caller. The idea is to prevent the cleaners from deleting
 * it while it's being used.
 *
 * You have to grab one of these references whenever you gain access to an entry. Keep in mind that
 * the session* and sessiondb* functions might have already done that for you.
 *
 * Remove the mark when you're done by calling session_return().
 */
void session_get(struct session_entry *session);

/**
 * Reverts the work of session_get() by removing the mark.
 *
 * If no other references to "session" exist, this function will take care of removing and freeing
 * it.
 *
 * DON'T USE "session" AFTER YOU RETURN IT! (unless you know you're holding another reference)
 */
int session_return(struct session_entry *session);


/********************************* Session Database *******************************/

/**
 * Call during initialization for the remaining functions to work properly.
 */
int sessiondb_init(void);
/**
 * Call during destruction to avoid memory leaks.
 */
void sessiondb_destroy(void);

/**
 * Copies the current configuration of the session database to "clone".
 */
int sessiondb_clone_config(struct sessiondb_config *clone);
/**
 * Updates the configuration value of this module whose identifier is "type".
 *
 * @param type ID of the configuration value you want to edit.
 * @size length of "value" in bytes.
 * @value the new value you want the field to have.
 */
int sessiondb_set_config(enum sessiondb_type type, size_t size, void *value);

/**
 * Returns in "result" the session entry you'd expect from the "tuple" tuple. That is, looks up
 * the session entry by both source and destination addresses.
 *
 * Once you have a reference to the entry, keep in mind that the database's timer might remove it
 * from the database while you're handling it. This shouldn't be a problem as long as you
 *
 * - keep the refcount this function reserves for you and
 * - you only want to read the const fields of the session.
 *
 * Make sure you decrement the refcount (session_return()) when you're done.
 *
 * @param[in] tuple summary of the packet. Describes the session you need.
 * @param[out] result the session entry you'd expect from the "tuple" tuple.
 * @return error status.
 *
 * O(log n), where n is the number of entries in the table.
 */
int sessiondb_get(struct tuple *tuple, struct session_entry **result);

/**
 * @{
 * An atomic way of saying something in the lines of
 *
 * session = sessiondb_get()
 * if (!session) {
 *     session = session_create()
 *     sessiondb_add(session)
 * }
 *
 * (that's pseudocode; don't swallow it literally.)
 */
int sessiondb_get_or_create_ipv6(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session);
int sessiondb_get_or_create_ipv4(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session);
/**
 * @}
 */

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
 * @param tuple summary of the packet.
 * @return whether there's a session entry with a source IPv4 transport address equal to "tuple"'s
 *		IPv4 destination transport address, and destination IPv4 address equal to "tuple"'s source
 *		address.
 *
 * O(log n), where n is the number of entries in the table.
 */
bool sessiondb_allow(struct tuple *tuple);

/**
 * Adds "session" to the database. Make sure you initialized "session" using session_create(),
 * please.
 *
 * @param session row to be added to the table.
 * @return error status.
 *
 * O(log n), where n is the number of entries in the table.
 */
int sessiondb_add(struct session_entry *session);

/**
 * Runs the "func" function for every session in the session table whose l4-protocol is "proto".
 * It sends each entry and "arg" to every call of "func".
 *
 * O(n), where n is the number of entries in the table.
 * Warning: This locks the table while you're iterating. You want to quit early if the tree is big.
 */
int sessiondb_for_each(l4_protocol proto, int (*func)(struct session_entry *, void *), void *arg);

/**
 * Similar to sessiondb_for_each(), except it only runs the function for sessions whose local IPv4
 * transport addresses are "addr".
 *
 * O(n), where n is the number of entries in the table whose local IPv4 addresses are "addr".
 * Warning: This locks the table while you're iterating. You want to quit early if the tree is big.
 */
int sessiondb_iterate_by_ipv4(l4_protocol proto, struct ipv4_tuple_address *addr, bool starting,
		int (*func)(struct session_entry *, void *), void *arg);

/**
 * Returns in "result" the number of sessions in the table whose l4-protocol is "proto".
 *
 * O(1).
 */
int sessiondb_count(l4_protocol proto, __u64 *result);

/**
 * Deletes from the "bib->l4_proto" table the session entries whose BIB entries are "bib".
 *
 * O(n), where n is the number of entries in the table whose BIB entries are "bib".
 */
int sessiondb_delete_by_bib(struct bib_entry *bib);

/**
 * Deletes from the database the session entries whose local IPv4 addresses are "addr4".
 *
 * O(n), where n is the number of entries in the DB whose local IPv4 addresses are "addr4".
 */
int sessiondb_delete_by_ipv4(struct in_addr *addr4);

/**
 * Deletes from the database the session entries whose local IPv6 addresses contain "prefix".
 *
 * O(n), where n is the number of entries in the DB whose local IPv6 addresses contain "prefix".
 */
int sessiondb_delete_by_ipv6_prefix(struct ipv6_prefix *prefix);

/**
 * Empties the entire database.
 *
 * O(n), where n is the number of entries in the entire database.
 */
int sessiondb_flush(void);

/**
 * Marks "session" to be destroyed after the UDP session lifetime has lapsed.
 * Same big O as mod_timer().
 */
void set_udp_timer(struct session_entry *session);

/**
 * Marks "session" to be destroyed after the ICMP session lifetime has lapsed.
 * Same big O as mod_timer().
 */
void set_icmp_timer(struct session_entry *session);

/**
 * Marks "session" to be destroyed after TCP_INCOMING_SYN seconds have lapsed.
 * Same big O as mod_timer().
 */
void set_syn_timer(struct session_entry *session);

/**
 * Updates "session"'s state based on "skb" and "tuple". This is a good chunk of section 3.5.2.2 of
 * RFC 6146.
 *
 * This should belong to the filtering module, but it gets so intimate with the database it's
 * unfeasible.
 */
int sessiondb_tcp_state_machine(struct sk_buff *skb, struct tuple *tuple,
		struct session_entry *session);

/**
 * Returns in "result" the amount of jiffies "session" is supposed to stay in memory.
 * If you want the jiffy at which the session is going to die, add this up to
 * "session->update_time".
 */
int sessiondb_get_timeout(struct session_entry *session, unsigned long *result);

#endif /* _JOOL_MOD_SESSION_DB_H */
