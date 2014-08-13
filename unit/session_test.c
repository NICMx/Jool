#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "session_db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Session module test.");

#define SESSION_PRINT_KEY "session [%pI4#%u, %pI4#%u, %pI6c#%u, %pI6c#%u]"
#define PRINT_SESSION(session) \
	&session->ipv4.remote.address, session->ipv4.remote.l4_id, \
	&session->ipv4.local.address, session->ipv4.local.l4_id, \
	&session->ipv6.local.address, session->ipv6.local.l4_id, \
	&session->ipv6.remote.address, session->ipv6.remote.l4_id

static const char* IPV4_ADDRS[] = { "0.0.0.0", "1.1.1.1", "2.2.2.2" };
static const __u16 IPV4_PORTS[] = { 0, 456, 9556 };
static const char* IPV6_ADDRS[] = { "::1", "::2", "::3" };
static const __u16 IPV6_PORTS[] = { 334, 0, 9556 };

static struct ipv4_tuple_address addr4[ARRAY_SIZE(IPV4_ADDRS)];
static struct ipv6_tuple_address addr6[ARRAY_SIZE(IPV6_ADDRS)];

/********************************************
 * Auxiliar functions.
 ********************************************/

static struct session_entry *create_session_entry(int remote_id_4, int local_id_4,
		int local_id_6, int remote_id_6,
		l4_protocol l4_proto)
{
	struct ipv4_pair pair_4 = {
			.remote = addr4[remote_id_4],
			.local = addr4[local_id_4],
	};

	struct ipv6_pair pair_6 = {
			.local = addr6[local_id_6],
			.remote = addr6[remote_id_6],
	};

	struct session_entry* entry = session_create(&pair_4, &pair_6, l4_proto, NULL);
	if (!entry)
		return NULL;

	log_debug(SESSION_PRINT_KEY, PRINT_SESSION(entry));

	return entry;
}

static struct session_entry *create_and_insert_session(int remote4_id, int local4_id, int local6_id,
		int remote6_id, l4_protocol l4_proto)
{
	struct session_entry *result;
	int error;

	result = create_session_entry(remote4_id, local4_id, local6_id, remote6_id, l4_proto);
	if (!result) {
		log_err("Could not allocate a session entry.");
		return NULL;
	}

	error = sessiondb_add(result);
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
			|| !ipv6_tuple_addr_equals(&expected->ipv6.remote, &actual->ipv6.remote)
			|| !ipv6_tuple_addr_equals(&expected->ipv6.local, &actual->ipv6.local)
			|| !ipv4_tuple_addr_equals(&expected->ipv4.local, &actual->ipv4.local)
			|| !ipv4_tuple_addr_equals(&expected->ipv4.remote, &actual->ipv4.remote)) {
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
		tuple4.dst.addr.ipv4 = session->ipv4.local.address;
		tuple4.dst.l4_id = session->ipv4.local.l4_id;
		tuple4.src.addr.ipv4 = session->ipv4.remote.address;
		tuple4.src.l4_id = session->ipv4.remote.l4_id;
		tuple4.l3_proto = L3PROTO_IPV4;
		tuple4.l4_proto = l4_protos[i];

		tuple6.dst.addr.ipv6 = session->ipv6.local.address;
		tuple6.dst.l4_id = session->ipv6.local.l4_id;
		tuple6.src.addr.ipv6 = session->ipv6.remote.address;
		tuple6.src.l4_id = session->ipv6.remote.l4_id;
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

/********************************************
 * Tests.
 ********************************************/

static bool simple_session(void)
{
	struct session_entry *session;
	bool success = true;

	session = create_session_entry(1, 0, 1, 0, L4PROTO_TCP);
	if (!assert_not_null(session, "Allocation of test session entry"))
		return false;

	success &= assert_equals_int(0, sessiondb_add(session), "Session insertion call");
	success &= assert_session("Session insertion state", session, false, true, false);
	if (!success)
		return false;

	return true;
}

static bool test_address_filtering_aux(int src_addr_id, int src_port_id, int dst_addr_id,
		int dst_port_id)
{
	struct tuple tuple;

	tuple.src.addr.ipv4 = addr4[src_addr_id].address;
	tuple.dst.addr.ipv4 = addr4[dst_addr_id].address;
	tuple.src.l4_id = addr4[src_port_id].l4_id;
	tuple.dst.l4_id = addr4[dst_port_id].l4_id;
	tuple.l4_proto = L4PROTO_UDP;
	tuple.l3_proto 	= L3PROTO_IPV4;

	log_tuple(&tuple);
	return sessiondb_allow(&tuple);
}

static bool test_address_filtering(void)
{
	struct session_entry *session;
	bool success = true;

	/* Init. */
	session = create_and_insert_session(0, 0, 0, 0, L4PROTO_UDP);
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

/********************************************
 * Main.
 ********************************************/

static bool init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		if (is_error(str_to_addr4(IPV4_ADDRS[i], &addr4[i].address)))
			return false;
		addr4[i].l4_id = IPV4_PORTS[i];
	}

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		if (is_error(str_to_addr6(IPV6_ADDRS[i], &addr6[i].address)))
			return false;
		addr6[i].l4_id = IPV6_PORTS[i];
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

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
