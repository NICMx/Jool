#include "nat64/mod/stateful/session/db.h"

#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/session/table.h"

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

static void just_die(struct session_entry *session, struct list_head *expires,
		struct list_head *probes)
{
	/* TODO */
}

int sessiondb_init(expire_fn tcpest_fn, expire_fn tcptrans_fn)
{
	int error;

	error = session_init();
	if (error)
		return error;

	sessiontable_init(&session_table_udp,
			config_get_ttl_udp,
			just_die, NULL, NULL);
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

	session_destroy();
}

int sessiondb_get(struct tuple *tuple, struct session_entry **result)
{
	return sessiontable_get(get_table(tuple->l4_proto), tuple, result);
}

bool sessiondb_allow(struct tuple *tuple4)
{
	return sessiontable_allow(get_table(tuple4->l4_proto), tuple4);
}

int sessiondb_add(struct session_entry *session, bool is_established)
{
	return sessiontable_add(get_table(session->l4_proto), session,
			is_established);
}

int sessiondb_foreach(l4_protocol proto,
		int (*func)(struct session_entry *, void *), void *arg,
		struct ipv4_transport_addr *offset_remote,
		struct ipv4_transport_addr *offset_local)
{
	return sessiontable_foreach(get_table(proto), func, arg,
			offset_remote, offset_local);
}

int sessiondb_count(l4_protocol proto, __u64 *result)
{
	return sessiontable_count(get_table(proto), result);
}

int sessiondb_delete_by_bib(struct bib_entry *bib)
{
	return sessiontable_delete_by_bib(get_table(bib->l4_proto), bib);
}

int sessiondb_delete_by_prefix4(struct ipv4_prefix *prefix)
{
	if (WARN(!prefix, "The IPv4 prefix is NULL"))
		return -EINVAL;

	sessiontable_delete_by_prefix4(&session_table_tcp, prefix);
	sessiontable_delete_by_prefix4(&session_table_icmp, prefix);
	sessiontable_delete_by_prefix4(&session_table_udp, prefix);

	return 0;
}

///**
// * Used in delete_sessions_by_prefix6 when is searching in the Session tree6,
// * returns zero if "session"->ipv6.local.address is equals to "prefix" or contains the "prefix".
// * Otherwise return the gap of the comparison result.
// */
//static int compare_local_prefix6(struct session_entry *session, struct ipv6_prefix *prefix)
//{
//	return (prefix6_contains(prefix, &session->local6.l3))
//			? 0
//			: ipv6_addr_cmp(&prefix->address, &session->local6.l3);
//}
//
///**
// * Deletes the sessions from the "table" table whose local IPv6 address contains "prefix".
// * This function is awfully similar to sessiondb_delete_by_bib(). See that for more comments.
// */
//static int delete_sessions_by_prefix6(struct session_table *table, struct ipv6_prefix *prefix)
//{
//	struct session_entry *root_session, *session;
//	struct rb_node *node;
//	int s = 0;
//
//	spin_lock_bh(&table->lock);
//
//	root_session = rbtree_find(prefix, &table->tree6, compare_local_prefix6, struct session_entry,
//			tree6_hook);
//	if (!root_session)
//		goto success;
//
//	node = rb_prev(&root_session->tree6_hook);
//	while (node) {
//		session = rb_entry(node, struct session_entry, tree6_hook);
//		node = rb_prev(&session->tree6_hook);
//
//		if (compare_local_prefix6(session, prefix) != 0)
//			break;
//		s += remove(session, table);
//	}
//
//	node = rb_next(&root_session->tree6_hook);
//	while (node) {
//		session = rb_entry(node, struct session_entry, tree6_hook);
//		node = rb_next(&session->tree6_hook);
//
//		if (compare_local_prefix6(session, prefix) != 0)
//			break;
//		s += remove(session, table);
//	}
//
//	s += remove(root_session, table);
//	table->count -= s;
//	/* Fall through. */
//
//success:
//	spin_unlock_bh(&table->lock);
//	log_debug("Deleted %d sessions.", s);
//	return 0;
//}
//
//int sessiondb_delete_by_prefix6(struct ipv6_prefix *prefix)
//{
//	if (WARN(!prefix, "The IPv6 prefix is NULL"))
//		return -EINVAL;
//
//	delete_sessions_by_prefix6(&session_table_tcp, prefix);
//	delete_sessions_by_prefix6(&session_table_icmp, prefix);
//	delete_sessions_by_prefix6(&session_table_udp, prefix);
//
//	return 0;
//}

int sessiondb_flush(void)
{
	log_debug("Emptying the session tables...");
	sessiontable_flush(&session_table_udp);
	sessiontable_flush(&session_table_tcp);
	sessiontable_flush(&session_table_icmp);
	return 0;
}

void sessiondb_update_timers(void)
{
	sessiontable_update_timers(&session_table_udp);
	sessiontable_update_timers(&session_table_tcp);
	sessiontable_update_timers(&session_table_icmp);
}
