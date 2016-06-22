#ifndef _JOOL_MOD_SESSION_DB_H
#define _JOOL_MOD_SESSION_DB_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 */

#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/bib/table.h"
#include "nat64/mod/stateful/session/table6.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

struct sessiondb;

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

int sessiondb_init(struct sessiondb **db);
void sessiondb_get(struct sessiondb *db);
void sessiondb_put(struct sessiondb *db);

void sessiondb_config_copy(struct sessiondb *db, struct session_config *config);
void sessiondb_config_set(struct sessiondb *db, struct session_config *config);

int sessiondb_find(struct sessiondb *db, struct tuple *tuple,
		fate_cb cb, void *cb_arg,
		struct session_entry **result);
/**
 * Full mapping finder package. Tries to yield both the BIB and session entries
 * that correspond to @tuple. (@tuple is assumed to be IPv4.)
 *
 * If a matching BIB is found,
 * - will initialize @bib as a copy of this entry,
 * - assign @session if it was also found (remember to session_put() it!),
 * - tell you whether the packet should be allowed through if Address-Dependent-
 *   Filtering is enabled (@allow)
 * - and return zero.
 *
 * If the BIB was not found, will return the corresponding error code. The
 * outgoing arguments will be undefined. (This function *cannot* succeed in
 * finding the session but fail to find the BIB entry.)
 */
int sessiondb_find_full(struct sessiondb *db, struct tuple *tuple4,
		struct bib_entry *bib, struct session_entry **session,
		bool *allow);
int sessiondb_find_bib(struct sessiondb *db, struct tuple *tuple,
		struct bib_entry *bib);

int sessiondb_queue(struct sessiondb *db, struct session_entry *session,
		struct packet *pkt);

int sessiondb_add(struct sessiondb *db, struct session_entry *session,
		fate_cb cb, void *cb_arg, bool est);
int sessiondb_add_simple(struct sessiondb *db, struct session_entry *session,
		bool est);

int sessiondb_foreach(struct sessiondb *db, l4_protocol proto,
		struct session_foreach_func *func,
		struct session_foreach_offset *offset);
int sessiondb_count(struct sessiondb *db, l4_protocol proto, __u64 *result);

void sessiondb_delete_by_bib(struct sessiondb *db, struct bib_entry *bib);
void sessiondb_rm_range(struct sessiondb *db, l4_protocol proto,
		struct ipv4_range *range);
void sessiondb_rm_prefix6(struct sessiondb *db, l4_protocol proto,
		struct ipv6_prefix *prefix);
void sessiondb_clean(struct sessiondb *db, struct net *ns);
void sessiondb_flush(struct sessiondb *db);

#endif /* _JOOL_MOD_SESSION_DB_H */
