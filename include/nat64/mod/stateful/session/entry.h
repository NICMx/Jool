#ifndef _JOOL_MOD_SESSION_ENTRY_H
#define _JOOL_MOD_SESSION_ENTRY_H

#include <linux/kref.h>
#include <linux/rbtree.h>
#include "nat64/common/types.h"
#include "nat64/common/session.h"
#include "nat64/mod/stateful/bib/db.h"

/**
 * A row, intended to be part of one of the session tables.
 * An IPv6 connection and the IPv4 version of it once translated.
 *
 * Please note that modifications to this structure may need to cascade to
 * "struct session_entry_usr".
 *
 * TODO (performance) this structure is somewhat big (probably 128+ bytes) and
 * there will be lots of sessions in memory. Maybe turn l4_proto into a
 * single-byte integer and remove some of the transport addresses (since they
 * can be extracted from @bib).
 */
struct session_entry {
	/**
	 * IPv6 version of the connection.
	 *
	 * "src" and "dst" are inherited names from the RFC. They are
	 * unfortunate, as they only make sense in the 6-to-4 direction.
	 *
	 * @src6 is the remote IPv6 node's transport address.
	 *     We used to call it "remote6".
	 * @dst6 is the address the NAT64 is using to mask the IPv4 endpoint.
	 *     We used to call it "local6".
	 */
	const struct ipv6_transport_addr src6;
	const struct ipv6_transport_addr dst6;

	/**
	 * IPv4 version of the connection.
	 *
	 * "src" and "dst" are inherited names from the RFC. They are
	 * unfortunate, as they only make sense in the 6-to-4 direction.
	 *
	 * @src4 is the address the NAT64 is using to mask the IPv6 endpoint.
	 *     We used to call it "local4".
	 * @dst4 is the remote IPv4 node's transport address.
	 *     We used to call it "remote4".
	 */
	const struct ipv4_transport_addr src4;
	const struct ipv4_transport_addr dst4;

	/** Transport protocol of the connection this session describes. */
	const l4_protocol l4_proto;
	/** Current TCP SM state. Only relevant if @l4_proto == L4PROTO_TCP. */
	tcp_state state;

	/** Jiffy (from the epoch) this session was last updated/used. */
	unsigned long update_time;

	/**
	 * When the session is in the database, this chains it to its
	 * corresponding expiration queue.
	 * The code can otherwise use it for other purposes. The expirer
	 * module, for example, uses it to chain sessions that need
	 * post-processing after a spinlock release.
	 */
	struct list_head list_hook;
	/** Timer supposed to delete this session when it expires. */
	struct expire_timer *expirer;
	/**
	 * Owner bib of this session. Used for quick access during removal.
	 * (when the session dies, the BIB might have to die too.)
	 */
	struct bib_entry *const bib;

	/** Appends this entry to the table's IPv6 index. */
	struct rb_node tree6_hook;
	/** Appends this entry to the table's IPv4 index. */
	struct rb_node tree4_hook;

	/** Reference counter for releasing purposes. */
	struct kref refs;
};

int session_init(void);
void session_destroy(void);

struct session_entry *session_create(const struct ipv6_transport_addr *src6,
		const struct ipv6_transport_addr *dst6,
		const struct ipv4_transport_addr *src4,
		const struct ipv4_transport_addr *dst4,
		l4_protocol l4_proto,
		struct bib_entry *bib);
struct session_entry *session_clone(struct session_entry *session);

void session_get(struct session_entry *session);
void session_put(struct session_entry *session, bool must_die);

bool session_equals(const struct session_entry *s1, const struct session_entry *s2);
void session_log(const struct session_entry *session, const char *action);

#endif /* _JOOL_MOD_SESSION_ENTRY_H */
