#ifndef _JOOL_MOD_SESSION_TABLE_H
#define _JOOL_MOD_SESSION_TABLE_H

#include <linux/timer.h>
#include "nat64/mod/stateful/session/entry.h"

struct session_table;

typedef unsigned long (*timeout_fn)(void);
typedef void (*expire_fn)(struct session_entry *, struct list_head *,
		struct list_head *);

struct expire_timer {
	struct timer_list timer;
	struct list_head sessions;
	timeout_fn get_timeout;
	expire_fn callback;
	struct session_table *table;
};

/**
 * Session table definition.
 * Holds red-black trees, one for each indexing need (IPv4 and IPv6).
 */
struct session_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;
	/** Number of session entries in this table. */
	u64 count;

	/** Expires this table's established sessions. */
	struct expire_timer est_timer;
	/** Expires this table's transitory sessions. */
	struct expire_timer trans_timer;

	/**
	 * Lock to sync access. This protects both the trees and the entries,
	 * but if you only need to read the const portion of the entries,
	 * you can get away with maintaining your reference count thingy.
	 */
	spinlock_t lock;
};

void sessiontable_init(struct session_table *table,
		timeout_fn est_timeout, expire_fn est_callback,
		timeout_fn trans_timeout, expire_fn trans_callback);
void sessiontable_destroy(struct session_table *table);

int sessiontable_get(struct session_table *table, struct tuple *tuple,
		struct session_entry **result);
int sessiontable_add(struct session_table *table, struct session_entry *session,
		bool is_established);

int sessiontable_foreach(struct session_table *table,
		int (*func)(struct session_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset_remote,
		const struct ipv4_transport_addr *offset_local);
int sessiontable_count(struct session_table *table, __u64 *result);

int sessiontable_delete_by_bib(struct session_table *table,
		struct bib_entry *bib);
int sessiontable_delete_by_prefix4(struct session_table *table,
		struct ipv4_prefix *prefix);
int sessiontable_flush(struct session_table *table);

bool sessiontable_allow(struct session_table *table, struct tuple *tuple4);
void sessiontable_update_timers(struct session_table *table);
int sessiontable_get_timeout(struct session_entry *session,
		unsigned long *result);

#endif /* _JOOL_MOD_SESSION_TABLE_H */
