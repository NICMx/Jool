#include "nat64/mod/stateful/session/db.h"

#include "nat64/common/constants.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/session/table.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

/**
 * One-liner to get the session table corresponding to the "l4_proto" protocol.
 *
 * Doesn't care about spinlocks.
 */
static struct session_table *get_table(struct sessiondb *db, l4_protocol l4_proto)
{
	switch (l4_proto) {
	case L4PROTO_UDP:
		return &db->udp;
	case L4PROTO_TCP:
		return &db->tcp;
	case L4PROTO_ICMP:
		return &db->icmp;
	case L4PROTO_OTHER:
		break;
	}

	WARN(true, "Unsupported transport protocol: %u.", l4_proto);
	return NULL;
}

static enum session_fate just_die(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

/* TODO maybe put this in some common header? */
enum session_fate tcp_expired_cb(struct session_entry *session, void *arg);

int sessiondb_init(struct sessiondb **db)
{
	struct sessiondb *result;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	sessiontable_init(&result->udp, UDP_DEFAULT, just_die, 0, NULL);
	sessiontable_init(&result->tcp, TCP_EST, tcp_expired_cb,
			TCP_TRANS, tcp_expired_cb);
	sessiontable_init(&result->icmp, ICMP_DEFAULT, just_die, 0, NULL);
	pktqueue_init(&result->pkt_queue);
	kref_init(&result->refcounter);

	*db = result;
	return 0;
}

void sessiondb_get(struct sessiondb *db)
{
	kref_get(&db->refcounter);
}

static void release(struct kref *refcounter)
{
	struct sessiondb *db;
	db = container_of(refcounter, typeof(*db), refcounter);

	log_debug("Emptying the session tables...");

	pktqueue_destroy(&db->pkt_queue);
	sessiontable_destroy(&db->udp);
	sessiontable_destroy(&db->tcp);
	sessiontable_destroy(&db->icmp);

	kfree(db);
}

void sessiondb_put(struct sessiondb *db)
{
	kref_put(&db->refcounter, release);
}

int sessiondb_find(struct sessiondb *db, struct tuple *tuple,
		fate_cb cb, void *cb_arg,
		struct session_entry **result)
{
	struct session_table *table = get_table(db, tuple->l4_proto);
	if (!table)
		return -EINVAL;
	return sessiontable_get(table, tuple, cb, cb_arg, result);
}

bool sessiondb_allow(struct sessiondb *db, struct tuple *tuple4)
{
	struct session_table *table = get_table(db, tuple4->l4_proto);
	return table ? sessiontable_allow(table, tuple4) : false;
}

int sessiondb_add(struct sessiondb *db, struct session_entry *session,
		bool is_est, bool is_synch)
{
	struct session_table *table = get_table(db, session->l4_proto);
	if (!table)
		return -EINVAL;

	pktqueue_rm(&db->pkt_queue, session);

	return sessiontable_add(table, session, is_est, is_synch);
}

bool sessiondb_is_session_established(struct sessiondb *db, struct session_entry *session)
{
	struct session_table *table = get_table(db, session->l4_proto);
	return session->expirer == &table->est_timer ? true : false;
}

int sessiondb_set_session_timer(struct sessiondb *db, struct session_entry *session, bool is_established)
{
	struct session_table *table = get_table(db, session->l4_proto);
	__u8 changed = 0;
	if (!table)
		return -EINVAL;

	if (is_established) {
		log_info("assinging est timer!");
		if (session->expirer != &table->est_timer) {
			changed = 1;
			session->expirer = &table->est_timer;
		}

	} else {
		log_info("assinging trans timer!");
		if (session->expirer != &table->est_timer) {
			changed = 1;
			session->expirer = &table->trans_timer;
		}
	}

	if (changed) {
		list_del(&session->list_hook);
		list_add_tail(&session->list_hook, &session->expirer->sessions);
		sessiontable_reschedule(session->expirer);
	}

	sessiontable_reschedule(session->expirer);

	return 0;
}

int sessiondb_foreach(struct sessiondb *db, l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local)
{
	struct session_table *table = get_table(db, proto);
	return table ? sessiontable_foreach(table, func, arg, offset_remote,
			offset_local) : -EINVAL;
}

int sessiondb_count(struct sessiondb *db, l4_protocol proto, __u64 *result)
{
	struct session_table *table = get_table(db, proto);
	return table ? sessiontable_count(table, result) : -EINVAL;
}

int sessiondb_delete_by_bib(struct sessiondb *db, struct bib_entry *bib)
{
	struct session_table *table = get_table(db, bib->l4_proto);
	if (!table)
		return -EINVAL;

	sessiontable_delete_by_bib(table, bib);
	return 0;
}

void sessiondb_delete_taddr4s(struct sessiondb *db, struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	sessiontable_delete_taddr4s(&db->tcp, prefix, ports);
	sessiontable_delete_taddr4s(&db->icmp, prefix, ports);
	sessiontable_delete_taddr4s(&db->udp, prefix, ports);
}

void sessiondb_delete_taddr6s(struct sessiondb *db, struct ipv6_prefix *prefix)
{
	sessiontable_delete_taddr6s(&db->tcp, prefix);
	sessiontable_delete_taddr6s(&db->icmp, prefix);
	sessiontable_delete_taddr6s(&db->udp, prefix);
}

void sessiondb_flush(struct sessiondb *db)
{
	log_debug("Emptying the session tables...");

	sessiontable_flush(&db->udp);
	sessiontable_flush(&db->tcp);
	sessiontable_flush(&db->icmp);
}

void sessiondb_update_timers(struct sessiondb *db)
{
	sessiontable_update_timers(&db->udp);
	sessiontable_update_timers(&db->tcp);
	sessiontable_update_timers(&db->icmp);
}
