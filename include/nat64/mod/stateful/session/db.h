#ifndef _JOOL_MOD_SESSION_DB_H
#define _JOOL_MOD_SESSION_DB_H

/**
 * @file
 * The Session tables.
 * Formally defined in RFC 6146 section 3.2.
 *
 * @author Alberto Leiva
 * @author Daniel Hernandez
 */

#include "nat64/mod/stateful/session/table.h"

int sessiondb_init(fate_cb tcpest_fn, fate_cb tcptrans_fn);
void sessiondb_destroy(void);

int sessiondb_get(struct tuple *tuple, fate_cb cb,
		struct session_entry **result);
int sessiondb_add(struct session_entry *session, bool is_established);

int sessiondb_foreach(l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local);
int sessiondb_count(l4_protocol proto, __u64 *result);

int sessiondb_delete_by_bib(struct bib_entry *bib);
int sessiondb_delete_by_prefix4(struct ipv4_prefix *prefix);
int sessiondb_delete_by_prefix6(struct ipv6_prefix *prefix);
int sessiondb_flush(void);

bool sessiondb_allow(struct tuple *tuple4);
void sessiondb_update_timers(void);

#endif /* _JOOL_MOD_SESSION_DB_H */
