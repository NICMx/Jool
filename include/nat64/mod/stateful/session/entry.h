#ifndef _JOOL_MOD_SESSION_ENTRY_H
#define _JOOL_MOD_SESSION_ENTRY_H

#include <linux/kref.h>
#include <linux/rbtree.h>
#include "nat64/common/types.h"
#include "nat64/mod/stateful/bib/db.h"

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
	const struct ipv6_transport_addr remote6;
	const struct ipv6_transport_addr local6;

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
	const struct ipv4_transport_addr local4;
	const struct ipv4_transport_addr remote4;

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
	 * When the session is in the database, this chains it to its
	 * corresponding expiration queue.
	 * Otherwise, the code can use it for other purposes. The expirer
	 * module, for example, uses it to chain sessions that need
	 * post-processing after a spinlock release.
	 */
	struct list_head list_hook;
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

int session_init(void);
void session_destroy(void);

struct session_entry *session_create(const struct ipv6_transport_addr *remote6,
		const struct ipv6_transport_addr *local6,
		const struct ipv4_transport_addr *local4,
		const struct ipv4_transport_addr *remote4,
		l4_protocol l4_proto, struct bib_entry *bib);
struct session_entry *session_clone(struct session_entry *session);

void session_get(struct session_entry *session);
int session_return(struct session_entry *session);

void session_log(const struct session_entry *session, const char *action);

#endif /* _JOOL_MOD_SESSION_ENTRY_H */
