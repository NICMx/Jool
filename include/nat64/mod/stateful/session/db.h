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

#include "nat64/mod/common/packet.h"
#include "nat64/mod/stateful/session/table.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

/**
 * TODO This is bad design; make this private.
 */
struct sessiondb {
	/** The session table for UDP conversations. */
	struct session_table udp;
	/** The session table for TCP connections. */
	struct session_table tcp;
	/** The session table for ICMP conversations. */
	struct session_table icmp;
	/** Packet storage for simultaneous open of TCP connections. */
	struct pktqueue pkt_queue;

	struct kref refcounter;
};

int sessiondb_init(struct sessiondb **db);
void sessiondb_get(struct sessiondb *db);
void sessiondb_put(struct sessiondb *db);

int sessiondb_find(struct sessiondb *db, struct tuple *tuple,
		fate_cb cb, void *cb_arg,
		struct session_entry **result);
int sessiondb_add(struct sessiondb *db, struct session_entry *session,
		bool is_established, bool is_synch);

int sessiondb_foreach(struct sessiondb *db, l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local);
int sessiondb_count(struct sessiondb *db, l4_protocol proto, __u64 *result);

int sessiondb_delete_by_bib(struct sessiondb *db, struct bib_entry *bib);
void sessiondb_delete_taddr4s(struct sessiondb *db, struct ipv4_prefix *prefix,
		struct port_range *ports);
void sessiondb_delete_taddr6s(struct sessiondb *db, struct ipv6_prefix *prefix);
void sessiondb_clean(struct sessiondb *db, struct net *ns);
void sessiondb_flush(struct sessiondb *db);

bool sessiondb_allow(struct sessiondb *db, struct tuple *tuple4);

int sessiondb_set_session_timer(struct sessiondb *db,
		struct session_entry *session, bool is_established);

#endif /* _JOOL_MOD_SESSION_DB_H */
