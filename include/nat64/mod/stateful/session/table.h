#ifndef _JOOL_MOD_SESSION_TABLE_H
#define _JOOL_MOD_SESSION_TABLE_H

#include <linux/timer.h>
#include "nat64/mod/stateful/session/entry.h"

enum session_fate {
	/**
	 * The session's timer has to be reset.
	 * While doing so, the session has to be considered established
	 * (ie. the session will not die soon).
	 */
	FATE_TIMER_EST,
	/**
	 * The session's timer has to be reset.
	 * While doing so, the session has to be considered transitory
	 * (ie. the session will die soon).
	 */
	FATE_TIMER_TRANS,
	/**
	 * The session expired; it has to be removed from the DB right away.
	 */
	FATE_RM,
	/**
	 * No changes.
	 */
	FATE_PRESERVE,
	/**
	 * Send a probe packet, then reset timer into transitory mode.
	 */
	FATE_PROBE,
};

typedef enum session_fate (*fate_cb)(struct session_entry *, void *);
typedef unsigned long (*timeout_cb)(void);

struct session_table;
struct expire_timer {
	struct timer_list timer;
	struct list_head sessions;
	timeout_cb get_timeout;
	fate_cb decide_fate_cb;
	struct session_table *table;
};

/**
 * Session table definition.
 * Holds red-black trees, one for each indexing need (IPv4 and IPv6).
 */
struct session_table {
	/**
	 * Indexes the entries using their IPv6 identifiers.
	 * (sorted by remote6, then local6.)
	 */
	struct rb_root tree6;
	/**
	 * Indexes the entries using their IPv4 identifiers.
	 * (sorted by local4, then remote4.)
	 */
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
		timeout_cb est_timeout, fate_cb est_callback,
		timeout_cb trans_timeout, fate_cb trans_callback);
void sessiontable_destroy(struct session_table *table);

int sessiontable_get(struct session_table *table, struct tuple *tuple,
		fate_cb cb, struct session_entry **result);
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

#endif /* _JOOL_MOD_SESSION_TABLE_H */
