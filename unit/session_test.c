#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/session.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "session_db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Session module test.");

#define TCPTRANS_TIMEOUT msecs_to_jiffies(1000 * TCP_TRANS)
#define TCPEST_TIMEOUT msecs_to_jiffies(1000 * TCP_EST)

#define SESSION_PRINT_KEY "session [%pI4#%u, %pI4#%u, %pI6c#%u, %pI6c#%u]"
#define PRINT_SESSION(session) \
	&session->remote4.l3, session->remote4.l4, \
	&session->local4.l3, session->local4.l4, \
	&session->local6.l3, session->local6.l4, \
	&session->remote6.l3, session->remote6.l4

static const char* IPV4_ADDRS[] = { "0.0.0.0", "1.1.1.1", "2.2.2.2" };
static const __u16 IPV4_PORTS[] = { 0, 456, 9556 };
static const char* IPV6_ADDRS[] = { "::1", "::2", "::3" };
static const __u16 IPV6_PORTS[] = { 334, 0, 9556 };

static struct ipv4_transport_addr addr4[ARRAY_SIZE(IPV4_ADDRS)];
static struct ipv6_transport_addr addr6[ARRAY_SIZE(IPV6_ADDRS)];

static struct session_entry *create_session_entry(int remote_id_4, int local_id_4,
		int local_id_6, int remote_id_6,
		l4_protocol l4_proto)
{
	struct session_entry* entry = session_create(&addr6[remote_id_6], &addr6[local_id_6],
			&addr4[local_id_4], &addr4[remote_id_4],
			l4_proto, NULL);
	if (!entry)
		return NULL;

	log_debug(SESSION_PRINT_KEY, PRINT_SESSION(entry));

	return entry;
}

static struct session_entry *create_and_insert_session(int remote4_id, int local4_id, int local6_id,
		int remote6_id)
{
	struct session_entry *result;
	int error;

	result = create_session_entry(remote4_id, local4_id, local6_id, remote6_id, L4PROTO_UDP);
	if (!result) {
		log_err("Could not allocate a session entry.");
		return NULL;
	}

	error = sessiondb_add(result, SESSIONTIMER_UDP);
	if (error) {
		log_err("Could not insert the session entry to the table; call returned %d.", error);
		return NULL;
	}

	return result;
}

static bool assert_session_entry_equals(struct session_entry* expected,
		struct session_entry* actual, char* test_name)
{
	if (expected == actual)
		return true;

	if (!expected) {
		log_err("Test '%s' failed: Expected null, obtained " SESSION_PRINT_KEY ".",
				test_name, PRINT_SESSION(actual));
		return false;
	}
	if (!actual) {
		log_err("Test '%s' failed: Expected " SESSION_PRINT_KEY ", got null.",
				test_name, PRINT_SESSION(expected));
		return false;
	}

	if (expected->l4_proto != actual->l4_proto
			|| !ipv6_transport_addr_equals(&expected->remote6, &actual->remote6)
			|| !ipv6_transport_addr_equals(&expected->local6, &actual->local6)
			|| !ipv4_transport_addr_equals(&expected->local4, &actual->local4)
			|| !ipv4_transport_addr_equals(&expected->remote4, &actual->remote4)) {
		log_err("Test '%s' failed: Expected " SESSION_PRINT_KEY ", got " SESSION_PRINT_KEY ".",
				test_name, PRINT_SESSION(expected), PRINT_SESSION(actual));
		return false;
	}

	return true;
}

/**
 * Same as assert_bib(), except asserting session entries on the session table.
 */
static bool assert_session(char* test_name, struct session_entry* session,
		bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
{
	struct session_entry *retrieved_session, *expected_session;
	struct tuple tuple6, tuple4;
	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
	bool table_has_it[3];
	bool success;
	int i;

	table_has_it[0] = udp_table_has_it;
	table_has_it[1] = tcp_table_has_it;
	table_has_it[2] = icmp_table_has_it;

	for (i = 0; i < 3; i++) {
		tuple4.dst.addr4 = session->local4;
		tuple4.src.addr4 = session->remote4;
		tuple4.l3_proto = L3PROTO_IPV4;
		tuple4.l4_proto = l4_protos[i];

		tuple6.dst.addr6 = session->local6;
		tuple6.src.addr6 = session->remote6;
		tuple6.l3_proto = L3PROTO_IPV6;
		tuple6.l4_proto = l4_protos[i];

		expected_session = table_has_it[i] ? session : NULL;
		success = true;

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				sessiondb_get(&tuple4, &retrieved_session),
				test_name);
		success &= assert_session_entry_equals(expected_session, retrieved_session, test_name);

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				sessiondb_get(&tuple6, &retrieved_session),
				test_name);
		success &= assert_session_entry_equals(expected_session, retrieved_session, test_name);

		if (!success)
			return false;
	}

	return true;
}

static bool simple_session(void)
{
	struct session_entry *session;
	bool success = true;

	session = create_session_entry(1, 0, 1, 0, L4PROTO_TCP);
	if (!assert_not_null(session, "Allocation of test session entry"))
		return false;

	success &= assert_equals_int(0, sessiondb_add(session, SESSIONTIMER_EST),
			"Session insertion call");
	success &= assert_session("Session insertion state", session, false, true, false);
	if (!success)
		return false;

	return true;
}

static bool test_address_filtering_aux(int src_addr_id, int src_port_id, int dst_addr_id,
		int dst_port_id)
{
	struct tuple tuple4;

	tuple4.src.addr4.l3 = addr4[src_addr_id].l3;
	tuple4.dst.addr4.l3 = addr4[dst_addr_id].l3;
	tuple4.src.addr4.l4 = addr4[src_port_id].l4;
	tuple4.dst.addr4.l4 = addr4[dst_port_id].l4;
	tuple4.l4_proto = L4PROTO_UDP;
	tuple4.l3_proto = L3PROTO_IPV4;

	log_tuple(&tuple4);
	return sessiondb_allow(&tuple4);
}

static bool test_address_filtering(void)
{
	struct session_entry *session;
	bool success = true;

	/* Init. */
	session = create_and_insert_session(0, 0, 0, 0);
	if (!session)
		return false;

	/* Test the packet is allowed when the tuple and session match perfectly. */
	success &= assert_true(test_address_filtering_aux(0, 0, 0, 0), "lol1");
	/* Test a tuple that completely mismatches the session. */
	success &= assert_false(test_address_filtering_aux(1, 1, 1, 1), "lol2");
	/* Now test tuples that nearly match the session. */
	success &= assert_false(test_address_filtering_aux(0, 0, 0, 1), "lol3");
	success &= assert_false(test_address_filtering_aux(0, 0, 1, 0), "lol4");
	/* The remote port is the only one that doesn't matter. */
	success &= assert_true(test_address_filtering_aux(0, 1, 0, 0), "lol5");
	success &= assert_false(test_address_filtering_aux(1, 0, 0, 0), "lol6");

	/* Now we erase the session entry */
	remove(session, &session_table_udp);
	session_return(session);
	session = NULL;

	/* Repeat the "lol5" test but now the assert must be false */
	success &= assert_false(test_address_filtering_aux(0, 1, 0, 0), "lol7");


	return success;
}
static bool test_sessiondb_timeouts_aux(struct expire_timer *expirer,
		unsigned int expirer_seconds, char *test_name)
{
	unsigned long mssec = msecs_to_jiffies(1000 * expirer_seconds);
	unsigned long timeout = get_timeout(expirer);

	return assert_equals_int(mssec, timeout, test_name);
}

static bool test_sessiondb_timeouts(void)
{

	bool success = true;

	success &= test_sessiondb_timeouts_aux(&expirer_udp, UDP_DEFAULT ,"UDP_timeout");
	success &= test_sessiondb_timeouts_aux(&expirer_icmp, ICMP_DEFAULT, "ICMP_timeout");
	success &= test_sessiondb_timeouts_aux(&expirer_tcp_est, TCP_EST, "TCP_EST_timeout");
	success &= test_sessiondb_timeouts_aux(&expirer_tcp_trans, TCP_TRANS,"TCP_TRANS_timeout");
	success &= test_sessiondb_timeouts_aux(&expirer_syn, TCP_INCOMING_SYN, "TCP_SYN_timeout");

	return success;
}

/*
 * A V6 SYN packet arrives.
 */
static bool test_tcp_v4_init_state_handle_v6syn(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_INIT);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, true, false, false))) {
		session_return(session);
		return false;
	}

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v4_init_state_handle(skb, session, &expirer),
			"V6 syn-result");
	success &= assert_equals_u8(ESTABLISHED, session->state, "V6 syn-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "V6 syn-toresult");
	success &= assert_equals_ulong(TCPEST_TIMEOUT, timeout, "V6 syn-lifetime");

	kfree_skb(skb);
	session_return(session);
	return success;
}

/*
 * Something else arrives.
 */
static bool test_tcp_v4_init_state_handle_else(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_INIT);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, false, true, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v4_init_state_handle(skb, session, &expirer), "else-result");
	success &= assert_null(session->expirer, "null expirer");

	kfree_skb(skb);
	return success;
}

/*
 * A V4 SYN packet arrives.
 */
static bool test_tcp_v6_init_state_handle_v4syn(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, true, false, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v6_init_state_handle(skb, session, &expirer), "V4 syn-result");
	success &= assert_equals_u8(ESTABLISHED, session->state, "V4 syn-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "V4 syn-toresult");
	success &= assert_equals_ulong(TCPEST_TIMEOUT, timeout, "V4 syn-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * A V6 SYN packet arrives.
 */
static bool test_tcp_v6_init_state_handle_v6syn(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, true, false, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v6_init_state_handle(skb, session, &expirer), "V6 syn-result");
	success &= assert_equals_u8(V6_INIT, session->state, "V6 syn-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "V6 syn-toresult");
	success &= assert_equals_ulong(TCPTRANS_TIMEOUT, timeout, "V6 syn-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * Something else arrives.
 */
static bool test_tcp_v6_init_state_handle_else(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, false, true, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v6_init_state_handle(skb, session, &expirer), "else-result");
	success &= assert_equals_u8(V6_INIT, session->state, "else-state");
	success &= assert_null(session->expirer, "null expirer");

	kfree_skb(skb);
	return success;
}
/*
 * A V4 FIN packet arrives.
 */
static bool test_tcp_established_state_handle_v4fin(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, false, false, true)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_established_state_handle(skb, session, &expirer), "result");
	success &= assert_equals_u8(V4_FIN_RCV, session->state, "V4 fin-state");
	success &= assert_null(session->expirer, "null expirer");

	kfree_skb(skb);
	return success;
}

/*
 * A V6 FIN packet arrives.
 */
static bool test_tcp_established_state_handle_v6fin(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, false, false, true)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_established_state_handle(skb, session, &expirer), "result");
	success &= assert_equals_u8(V6_FIN_RCV, session->state, "V6 fin-state");
	success &= assert_null(session->expirer, "null expirer");

	kfree_skb(skb);
	return success;
}

/*
 * A V4 RST packet arrives.
 */
static bool test_tcp_established_state_handle_v4rst(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, false, true, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_established_state_handle(skb, session, &expirer), "result");
	success &= assert_equals_u8(TRANS, session->state, "V4 rst-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "V4 rst-toresult");
	success &= assert_equals_ulong(TCPTRANS_TIMEOUT, timeout, "V4 rst-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * A V6 RST packet arrives.
 */
static bool test_tcp_established_state_handle_v6rst(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, false, true, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_established_state_handle(skb, session, &expirer), "result");
	success &= assert_equals_u8(TRANS, session->state, "V6 rst-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "V6 rst-toresult");
	success &= assert_equals_ulong(TCPTRANS_TIMEOUT, timeout, "V6 rst-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * Something else arrives.
 */
static bool test_tcp_established_state_handle_else(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, true, false, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_established_state_handle(skb, session, &expirer), "result");
	success &= assert_equals_u8(ESTABLISHED, session->state, "else-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "else-toresult");
	success &= assert_equals_ulong(TCPEST_TIMEOUT, timeout, "else-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * A V6 FIN packet arrives.
 */
static bool test_tcp_v4_fin_rcv_state_handle_v6fin(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_FIN_RCV);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, false, false, true)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v4_fin_rcv_state_handle(skb, session, &expirer), "V6 fin-result");
	success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session->state, "V6 fin-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "V6 fin-toresult");
	success &= assert_equals_ulong(TCPTRANS_TIMEOUT, timeout, "V6 fin-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * Something else arrives.
 */
static bool test_tcp_v4_fin_rcv_state_handle_else(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_FIN_RCV);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, true, false, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v4_fin_rcv_state_handle(skb, session, &expirer), "else-result");
	success &= assert_equals_u8(V4_FIN_RCV, session->state, "else-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "else-toresult");
	success &= assert_equals_ulong(TCPEST_TIMEOUT, timeout, "else-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * A V4 FIN packet arrives.
 */
static bool test_tcp_v6_fin_rcv_state_handle_v4fin(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_FIN_RCV);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, false, false, true)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v6_fin_rcv_state_handle(skb, session, &expirer), "V4 fin-result");
	success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session->state, "V4 fin-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "V4 fin-toresult");
	success &= assert_equals_ulong(TCPTRANS_TIMEOUT, timeout, "V4 fin-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * Something else arrives.
 */
static bool test_tcp_v6_fin_rcv_state_handle_else(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_FIN_RCV);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, true, false, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_v6_fin_rcv_state_handle(skb, session, &expirer), "else-result");
	success &= assert_equals_u8(V6_FIN_RCV, session->state, "else-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "else-toresult");
	success &= assert_equals_ulong(TCPEST_TIMEOUT, timeout, "else-lifetime");

	kfree_skb(skb);
	return success;
}

/*
 * A V4 RST packet arrives.
 */
static bool test_tcp_trans_state_handle_v4rst(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, false, true, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_trans_state_handle(skb, session, &expirer), "V4 rst-result");
	success &= assert_equals_u8(TRANS, session->state, "V4 rst-state");
	success &= assert_null(session->expirer, "null expirer");

	kfree_skb(skb);
	return success;
}

/*
* A V6 RST packet arrives.
*/
static bool test_tcp_trans_state_handle_v6rst(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV6, false, true, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_trans_state_handle(skb, session, &expirer), "V6 rst-result");
	success &= assert_equals_u8(TRANS, session->state, "V6 rst-state");
	success &= assert_null(session->expirer, "null expirer");

	kfree_skb(skb);
	return success;
}

/*
 * Something else arrives.
 */
static bool test_tcp_trans_state_handle_else(void)
{
	struct session_entry *session;
	struct expire_timer *expirer;
	struct sk_buff *skb;
	unsigned long timeout;
	bool success = true;

	/* Prepare */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS);
	if (!session)
		return false;
	if (is_error(create_tcp_packet(&skb, L3PROTO_IPV4, true, false, false)))
		return false;

	/* Evaluate */
	success &= assert_equals_int(0, tcp_trans_state_handle(skb, session, &expirer), "else-result");
	success &= assert_equals_u8(ESTABLISHED, session->state, "else-state");
	success &= assert_equals_int(0, sessiondb_get_timeout(session, &timeout), "else-toresult");
	success &= assert_equals_ulong(TCPEST_TIMEOUT, timeout, "else-lifetime");

	kfree_skb(skb);
	return success;
}

static bool init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		if (is_error(str_to_addr4(IPV4_ADDRS[i], &addr4[i].l3)))
			return false;
		addr4[i].l4 = IPV4_PORTS[i];
	}

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		if (is_error(str_to_addr6(IPV6_ADDRS[i], &addr6[i].l3)))
			return false;
		addr6[i].l4 = IPV6_PORTS[i];
	}

	if (is_error(sessiondb_init()))
		return false;
	if (is_error(pktqueue_init()))
		return false;

	return true;
}

static void end(void)
{
	sessiondb_destroy();
	pktqueue_destroy();
}

int init_module(void)
{
	START_TESTS("Session");

	INIT_CALL_END(init(), simple_session(), end(), "Single Session");
	INIT_CALL_END(init(), test_address_filtering(), end(), "Address-dependent filtering.");
	INIT_CALL_END(init(), test_sessiondb_timeouts(), end(), "Session config timeouts");

	INIT_CALL_END(init(), test_tcp_v4_init_state_handle_v6syn(), end(), "TCP-V4 INIT-V6 syn");
	INIT_CALL_END(init(), test_tcp_v4_init_state_handle_else(), end(), "TCP-V4 INIT-else");
	INIT_CALL_END(init(), test_tcp_v6_init_state_handle_v6syn(), end(), "TCP-V6 INIT-V6 SYN");
	INIT_CALL_END(init(), test_tcp_v6_init_state_handle_v4syn(), end(), "TCP-V6 INIT-V4 SYN");
	INIT_CALL_END(init(), test_tcp_v6_init_state_handle_else(), end(), "TCP-V6 INIT-else");
	INIT_CALL_END(init(), test_tcp_established_state_handle_v4fin(), end(), "TCP-established-V4 fin");
	INIT_CALL_END(init(), test_tcp_established_state_handle_v6fin(), end(), "TCP-established-V6 fin");
	INIT_CALL_END(init(), test_tcp_established_state_handle_v4rst(), end(), "TCP-established-V4 rst");
	INIT_CALL_END(init(), test_tcp_established_state_handle_v6rst(), end(), "TCP-established-V6 rst");
	INIT_CALL_END(init(), test_tcp_established_state_handle_else(), end(), "TCP-established-else");
	INIT_CALL_END(init(), test_tcp_v4_fin_rcv_state_handle_v6fin(), end(), "TCP-V4 FIN RCV-V6 fin");
	INIT_CALL_END(init(), test_tcp_v4_fin_rcv_state_handle_else(), end(), "TCP-V4 FIN RCV-else");
	INIT_CALL_END(init(), test_tcp_v6_fin_rcv_state_handle_v4fin(), end(), "TCP-V6 FIN RCV-v4fin");
	INIT_CALL_END(init(), test_tcp_v6_fin_rcv_state_handle_else(), end(), "TCP-V6 FIN RCV-else");
	INIT_CALL_END(init(), test_tcp_trans_state_handle_v6rst(), end(), "TCP-TRANS-V6 rst");
	INIT_CALL_END(init(), test_tcp_trans_state_handle_v4rst(), end(), "TCP-TRANS-V4 rst");
	INIT_CALL_END(init(), test_tcp_trans_state_handle_else(), end(), "TCP-TRANS-else");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
