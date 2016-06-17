#ifndef _JOOL_MOD_SESSION_DB_H
#define _JOOL_MOD_SESSION_DB_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 */

#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/session/table.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

struct sessiondb;

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
		fate_cb cb, void *cb_args,
		bool est_timer);
int sessiondb_add_simple(struct sessiondb *db, struct session_entry *session,
		bool est_timer);

int sessiondb_foreach(struct sessiondb *db, l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local,
		const bool include_offset);
int sessiondb_count(struct sessiondb *db, l4_protocol proto, __u64 *result);

int sessiondb_delete_by_bib(struct sessiondb *db, struct bib_entry *bib);
void sessiondb_rm_taddr4s(struct sessiondb *db, struct ipv4_prefix *prefix,
		struct port_range *ports);
void sessiondb_rm_taddr6s(struct sessiondb *db, struct ipv6_prefix *prefix);
void sessiondb_clean(struct sessiondb *db, struct net *ns);
void sessiondb_flush(struct sessiondb *db);

bool sessiondb_allow(struct sessiondb *db, struct tuple *tuple4);

#endif /* _JOOL_MOD_SESSION_DB_H */
