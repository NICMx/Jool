#include "nat64/mod/stateful/session/db.h"

#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/session/table.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

/** The session table for UDP conversations. */
static struct session_table session_table_udp;
/** The session table for TCP connections. */
static struct session_table session_table_tcp;
/** The session table for ICMP conversations. */
static struct session_table session_table_icmp;

/**
 * One-liner to get the session table corresponding to the "l4_proto" protocol.
 *
 * Doesn't care about spinlocks.
 */
static struct session_table *get_table(l4_protocol l4_proto)
{
	switch (l4_proto) {
	case L4PROTO_UDP:
		return &session_table_udp;
	case L4PROTO_TCP:
		return &session_table_tcp;
	case L4PROTO_ICMP:
		return &session_table_icmp;
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

int sessiondb_init(fate_cb tcpest_fn, fate_cb tcptrans_fn)
{
	int error;

	error = session_init();
	if (error)
		return error;
	error = pktqueue_init();
	if (error) {
		session_destroy();
		return error;
	}

	sessiontable_init(&session_table_udp,
			config_get_ttl_udp, just_die,
			NULL, NULL);
	sessiontable_init(&session_table_tcp,
			config_get_ttl_tcpest, tcpest_fn,
			config_get_ttl_tcptrans, tcptrans_fn);
	sessiontable_init(&session_table_icmp,
			config_get_ttl_icmp, just_die,
			NULL, NULL);

	return 0;
}


void sessiondb_destroy(void)
{
	log_debug("Emptying the session tables...");

	sessiontable_destroy(&session_table_udp);
	sessiontable_destroy(&session_table_tcp);
	sessiontable_destroy(&session_table_icmp);

	pktqueue_destroy();
	session_destroy();
}

int sessiondb_get(struct tuple *tuple, fate_cb cb,
		struct session_entry **result)
{
	struct session_table *table = get_table(tuple->l4_proto);
	return table ? sessiontable_get(table, tuple, cb, result) : -EINVAL;
}

bool sessiondb_allow(struct tuple *tuple4)
{
	struct session_table *table = get_table(tuple4->l4_proto);
	return table ? sessiontable_allow(table, tuple4) : false;
}

int sessiondb_add(struct session_entry *session, bool is_est)
{
	struct session_table *table = get_table(session->l4_proto);
	return table ? sessiontable_add(table, session, is_est) : -EINVAL;
}

int sessiondb_foreach(l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local)
{
	struct session_table *table = get_table(proto);
	return table ? sessiontable_foreach(table, func, arg, offset_remote,
			offset_local) : -EINVAL;
}

int sessiondb_count(l4_protocol proto, __u64 *result)
{
	struct session_table *table = get_table(proto);
	return table ? sessiontable_count(table, result) : -EINVAL;
}

int sessiondb_delete_by_bib(struct bib_entry *bib)
{
	struct session_table *table = get_table(bib->l4_proto);
	if (!table)
		return -EINVAL;

	sessiontable_delete_by_bib(table, bib);
	return 0;
}

void sessiondb_delete_taddr4s(struct ipv4_prefix *prefix,
		struct port_range *ports)
{
	sessiontable_delete_taddr4s(&session_table_tcp, prefix, ports);
	sessiontable_delete_taddr4s(&session_table_icmp, prefix, ports);
	sessiontable_delete_taddr4s(&session_table_udp, prefix, ports);
}

void sessiondb_delete_taddr6s(struct ipv6_prefix *prefix)
{
	sessiontable_delete_taddr6s(&session_table_tcp, prefix);
	sessiontable_delete_taddr6s(&session_table_icmp, prefix);
	sessiontable_delete_taddr6s(&session_table_udp, prefix);
}

void sessiondb_flush(void)
{
	log_debug("Emptying the session tables...");

	sessiontable_flush(&session_table_udp);
	sessiontable_flush(&session_table_tcp);
	sessiontable_flush(&session_table_icmp);
}

void sessiondb_update_timers(void)
{
	sessiontable_update_timers(&session_table_udp);
	sessiontable_update_timers(&session_table_tcp);
	sessiontable_update_timers(&session_table_icmp);
}
