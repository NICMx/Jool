#ifndef _JOOL_MOD_SESSION_TABLE_H
#define _JOOL_MOD_SESSION_TABLE_H

#include <linux/timer.h>
#include "nat64/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/bib/table.h"
#include "nat64/mod/stateful/session/entry.h"

enum session_fate {
	/**
	 * Assign the established timer to the session.
	 * (An "established" timer is one where it is assumed the session is
	 * not going to die soon.)
	 */
	FATE_TIMER_EST,
	/**
	 * Assign the transitory timer to the session.
	 * (A "transitory" timer is one where it is assumed the session is
	 * going to die soon.)
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

	/**
	 * Like FATE_TIMER_EST, except the session's lifetime must not be reset.
	 * It's called "slow" because this means the database cannot just add
	 * the session to the end of the sorted (by expiration date) list and so
	 * the proper slot has to be found in a sequential search.
	 */
	FATE_TIMER_EST_SLOW,
	/**
	 * Like FATE_TIMER_TRANS, except the session's lifetime must not be
	 * reset.
	 * It's called "slow" because this means the database cannot just add
	 * the session to the end of the sorted (by expiration date) list and so
	 * the proper slot has to be found in a sequential search.
	 */
	FATE_TIMER_TRANS_SLOW,
};

typedef enum session_fate (*fate_cb)(struct session_entry *, void *);
typedef unsigned long (*timeout_cb)(struct global_config *);

struct expire_timer {
	struct list_head sessions;
	unsigned long timeout;
	bool is_established;
	fate_cb decide_fate_cb;
};

struct session_table;

void sessiontable_init(struct session_table *table, fate_cb expired_cb,
		int est_timeout, int trans_timeout);
void sessiontable_destroy(struct session_table *table);

void sessiontable_config_copy(struct session_table *table,
		struct session_config *config,
		enum l4_protocol proto);
void sessiontable_config_set(struct session_table *table,
		struct session_config *config,
		enum l4_protocol proto);

int sessiontable_find(struct session_table *table, struct tuple *tuple,
		fate_cb cb, void *cb_arg,
		struct session_entry **result);
int sessiontable_add(struct session_table *table, struct session_entry *session,
		fate_cb cb, void *cb_args, bool est);

int sessiontable_foreach(struct session_table *table,
		int (*func)(struct session_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset_remote,
		const struct ipv4_transport_addr *offset_local,
		const bool include_offset);
int sessiontable_count(struct session_table *table, __u64 *result);

void sessiontable_delete_by_bib(struct session_table *table,
		struct bib_entry *bib);
void sessiontable_rm_taddr4s(struct session_table *table,
		struct ipv4_prefix *prefix, struct port_range *ports);
void sessiontable_rm_taddr6s(struct session_table *table,
		struct ipv6_prefix *prefix);
void sessiontable_clean(struct session_table *table, struct net *ns);
void sessiontable_flush(struct session_table *table);

bool sessiontable_allow(struct session_table *table, struct tuple *tuple4);

#endif /* _JOOL_MOD_SESSION_TABLE_H */
