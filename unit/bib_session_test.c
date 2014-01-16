#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/bib.h"
#include "session.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("BIB-Session module test.");

#define BIB_PRINT_KEY "BIB [%pI4#%u, %pI6c#%u]"
#define SESSION_PRINT_KEY "session [%pI4#%u, %pI4#%u, %pI6c#%u, %pI6c#%u]"
#define PRINT_BIB(bib) \
	&bib->ipv4.address, bib->ipv4.l4_id, \
	&bib->ipv6.address, bib->ipv6.l4_id
#define PRINT_SESSION(session) \
	&session->ipv4.remote.address, session->ipv4.remote.l4_id, \
	&session->ipv4.local.address, session->ipv4.local.l4_id, \
	&session->ipv6.local.address, session->ipv6.local.l4_id, \
	&session->ipv6.remote.address, session->ipv6.remote.l4_id

static const char* IPV4_ADDRS[] = { "0.0.0.0", "255.1.2.3", "65.0.123.2", "0.1.0.3",
		"55.55.55.55", "10.11.12.13", "13.12.11.10", "255.255.255.255",
		"1.2.3.4", "4.3.2.1", "2.3.4.5", "5.4.3.2",
		"3.4.5.6", "6.5.4.3", "4.5.6.7", "7.6.5.4",
		"56.56.56.56" };
static const __u16 IPV4_PORTS[] = { 0, 456, 9556, 7523,
		65535, 536, 284, 231,
		1234, 4321, 2345, 5432,
		3456, 6543, 4567, 7654,
		6384 };
static const char* IPV6_ADDRS[] = { "::1", "5:3::2", "4::", "44:55:66::",
		"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "123::4", "::0", "44:1:1::2:9",
		"1:2:3:4::", "4:3:2:1::", "2:3:4:5::", "5:4:3:2::",
		"3:4:5:6::", "6:5:4:3::", "4:5:6:7::", "7:6:5:4::",
		"56:56:56:56::" };
static const __u16 IPV6_PORTS[] = { 334, 0, 9556, 65535,
		55555, 825, 1111, 99,
		1234, 4321, 2345, 5432,
		3456, 6543, 4567, 7654,
		6384 };

static struct ipv4_tuple_address addr4[ARRAY_SIZE(IPV4_ADDRS)];
static struct ipv6_tuple_address addr6[ARRAY_SIZE(IPV6_ADDRS)];

/********************************************
 * Auxiliar functions.
 ********************************************/

static struct bib_entry *create_bib_entry(int ipv4_index, int ipv6_index)
{
	return bib_create(&addr4[ipv4_index], &addr6[ipv6_index], false);
}

static struct session_entry *create_session_entry(int remote_id_4, int local_id_4,
		int local_id_6, int remote_id_6,
		struct bib_entry* bib, l4_protocol l4_proto, unsigned int dying_time)
{
	struct ipv4_pair pair_4 = {
			.remote = addr4[remote_id_4],
			.local = addr4[local_id_4],
	};
	struct ipv6_pair pair_6 = {
			.local = addr6[local_id_6],
			.remote = addr6[remote_id_6],
	};

	struct session_entry* entry = session_create(&pair_4, &pair_6, l4_proto);
	if (!entry)
		return NULL;

	entry->dying_time = dying_time;
	if (bib) {
		entry->bib = bib;
		list_add(&entry->bib_list_hook, &bib->sessions);
	}

	return entry;
}

static bool bib_entry_equals(struct bib_entry *bib_1, struct bib_entry *bib_2)
{
	if (bib_1 == bib_2)
		return true;
	if (!bib_1 || !bib_2)
		return false;

	if (!ipv4_tuple_addr_equals(&bib_1->ipv4, &bib_2->ipv4))
		return false;
	if (!ipv6_tuple_addr_equals(&bib_1->ipv6, &bib_2->ipv6))
		return false;

	return true;
}

static bool session_entry_equals(struct session_entry *session_1, struct session_entry *session_2)
{
	if (session_1 == session_2)
		return true;
	if (session_1 == NULL || session_2 == NULL)
		return false;

	if (session_1->l4_proto != session_2->l4_proto)
		return false;
	if (!ipv6_tuple_addr_equals(&session_1->ipv6.remote, &session_2->ipv6.remote))
		return false;
	if (!ipv6_tuple_addr_equals(&session_1->ipv6.local, &session_2->ipv6.local))
		return false;
	if (!ipv4_tuple_addr_equals(&session_1->ipv4.local, &session_2->ipv4.local))
		return false;
	if (!ipv4_tuple_addr_equals(&session_1->ipv4.remote, &session_2->ipv4.remote))
		return false;

	return true;
}

static struct bib_entry *create_and_insert_bib(int ipv4_index, int ipv6_index, int l4proto)
{
	struct bib_entry *result;
	int error;

	result = create_bib_entry(ipv4_index, ipv6_index);
	if (!result) {
		log_warning("Could not allocate a BIB entry.");
		return NULL;
	}

	error = bib_add(result, l4proto);
	if (error) {
		log_warning("Could not insert the BIB entry to the table; call returned %d.", error);
		return NULL;
	}

	return result;
}

static struct session_entry *create_and_insert_session(int remote4_id, int local4_id, int local6_id,
		int remote6_id, struct bib_entry* bib, l4_protocol l4_proto, unsigned int dying_time)
{
	struct session_entry *result;
	int error;

	result = create_session_entry(remote4_id, local4_id, local6_id, remote6_id, bib, l4_proto,
			dying_time);
	if (!result) {
		log_warning("Could not allocate a session entry.");
		return NULL;
	}

	error = session_add(result);
	if (error) {
		log_warning("Could not insert the session entry to the table; call returned %d.", error);
		return NULL;
	}

	return result;
}

static bool assert_bib_entry_equals(struct bib_entry* expected, struct bib_entry* actual,
		char* test_name)
{
	if (expected == actual)
		return true;

	if (expected == NULL) {
		log_warning("Test '%s' failed: Expected null, got " BIB_PRINT_KEY ".",
				test_name, PRINT_BIB(actual));
		return false;
	}
	if (actual == NULL) {
		log_warning("Test '%s' failed: Expected " BIB_PRINT_KEY ", got null.",
				test_name, PRINT_BIB(expected));
		return false;
	}
	if (!bib_entry_equals(expected, actual)) {
		log_warning("Test '%s' failed: Expected " BIB_PRINT_KEY " got " BIB_PRINT_KEY ".",
				test_name, PRINT_BIB(expected), PRINT_BIB(actual));
		return false;
	}

	return true;
}

static bool assert_session_entry_equals(struct session_entry* expected,
		struct session_entry* actual, char* test_name)
{
	if (expected == actual)
		return true;

	if (expected == NULL) {
		log_warning("Test '%s' failed: Expected null, obtained " SESSION_PRINT_KEY ".",
				test_name, PRINT_SESSION(actual));
		return false;
	}
	if (actual == NULL) {
		log_warning("Test '%s' failed: Expected " SESSION_PRINT_KEY ", got null.",
				test_name, PRINT_SESSION(expected));
		return false;
	}
	if (!session_entry_equals(expected, actual)) {
		log_warning("Test '%s' failed: Expected " SESSION_PRINT_KEY ", got " SESSION_PRINT_KEY ".",
				test_name, PRINT_SESSION(expected), PRINT_SESSION(actual));
		return false;
	}

	return true;
}

/**
 * Asserts the "bib" entry was correctly inserted into the tables.
 * -> if udp_table_has_it, will test the entry exists and is correctly indexed by the UDP table.
 *    Else it will assert the bib is not indexed by the UDP table.
 * -> if tcp_table_has_it, will test the entry exists and is correctly indexed by the TCP table.
 *    Else it will assert the bib is not indexed by the TCP table.
 * -> if icmp_table_has_it, will test the entry exists and is correctly indexed by the ICMP table.
 *    Else it will assert the bib is not indexed by the ICMP table.
 */
static bool assert_bib(char* test_name, struct bib_entry* bib,
		bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
{
	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
	bool table_has_it[3];
	int i;

	table_has_it[0] = udp_table_has_it;
	table_has_it[1] = tcp_table_has_it;
	table_has_it[2] = icmp_table_has_it;

	for (i = 0; i < 3; i++) {
		struct bib_entry *expected_bib = table_has_it[i] ? bib : NULL;
		struct bib_entry *retrieved_bib;
		int success = true;

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				bib_get_by_ipv4(&bib->ipv4, l4_protos[i], &retrieved_bib),
				test_name);
		success &= assert_bib_entry_equals(expected_bib, retrieved_bib, test_name);

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				bib_get_by_ipv6(&bib->ipv6, l4_protos[i], &retrieved_bib),
				test_name);
		success &= assert_bib_entry_equals(expected_bib, retrieved_bib, test_name);

		if (!success)
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
	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
	bool table_has_it[3];
	int i;

	table_has_it[0] = udp_table_has_it;
	table_has_it[1] = tcp_table_has_it;
	table_has_it[2] = icmp_table_has_it;

	for (i = 0; i < 3; i++) {
		struct ipv4_pair pair_4 = { session->ipv4.remote, session->ipv4.local };
		struct ipv6_pair pair_6 = { session->ipv6.local, session->ipv6.remote };
		struct session_entry *expected_session = table_has_it[i] ? session : NULL;
		struct session_entry *retrieved_session;
		bool success = true;

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				session_get_by_ipv4(&pair_4, l4_protos[i], &retrieved_session),
				test_name);
		success &= assert_session_entry_equals(expected_session, retrieved_session, test_name);

		success &= assert_equals_int(table_has_it[i] ? 0 : -ENOENT,
				session_get_by_ipv6(&pair_6, l4_protos[i], &retrieved_session),
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

/**
 * Inserts a single entry, validates it, removes it, validates again.
 * Does not touch the session tables.
 */
static bool simple_bib(void)
{
	struct bib_entry *bib;
	bool success = true;

	bib = create_bib_entry(0, 0);
	if (!assert_not_null(bib, "Allocation of test BIB entry"))
		return false;

	success &= assert_equals_int(0, bib_add(bib, L4PROTO_TCP), "BIB insertion call");
	success &= assert_bib("BIB insertion state", bib, false, true, false);
	if (!success)
		return false;

	success &= assert_equals_int(0, bib_remove(bib, L4PROTO_TCP), "BIB removal call");
	success &= assert_bib("BIB removal state", bib, false, false, false);
	if (!success)
		return false;

	bib_kfree(bib);
	return success;
}

static bool simple_session(void)
{
	struct session_entry *session;
	bool success = true;

	session = create_session_entry(1, 0, 1, 0, NULL, L4PROTO_TCP, 12345);
	if (!assert_not_null(session, "Allocation of test session entry"))
		return false;

	success &= assert_equals_int(0, session_add(session), "Session insertion call");
	success &= assert_session("Session insertion state", session, false, true, false);
	if (!success)
		return false; /* See simple_bib(). */

	success &= assert_equals_int(0, session_remove(session), "Session removal call");
	success &= assert_session("Session removal state", session, false, false, false);
	if (!success)
		return false;

	session_kfree(session);
	return true;
}

static bool test_address_filtering_aux(int src_addr_id, int src_port_id, int dst_addr_id,
		int dst_port_id)
{
	struct tuple tuple;

	tuple.src.addr.ipv4 = addr4[src_addr_id].address;
	tuple.dst.addr.ipv4 = addr4[dst_addr_id].address;
	tuple.src.l4_id = IPV4_PORTS[src_port_id];
	tuple.dst.l4_id = IPV4_PORTS[dst_port_id];
	tuple.l4_proto = L4PROTO_UDP;
	tuple.l3_proto 	= L3PROTO_IPV4;

	return session_allow(&tuple);
}

static bool test_address_filtering(void)
{
	struct bib_entry *bib;
	struct session_entry *session;
	bool success = true;

	/* Init. */
	bib = create_and_insert_bib(0, 0, L4PROTO_UDP);
	if (!bib)
		return false;
	session = create_and_insert_session(0, 0, 0, 0, bib, L4PROTO_UDP, 12345);
	if (!session)
		return false;

	/* Test the packet is allowed when the tuple and session match perfectly. */
	success &= assert_true(test_address_filtering_aux(0, 0, 0, 0), "");
	/* Test a tuple that completely mismatches the session. */
	success &= assert_false(test_address_filtering_aux(1, 1, 1, 1), "");
	/* Now test tuples that nearly match the session. */
	success &= assert_false(test_address_filtering_aux(0, 0, 0, 1), "");
	success &= assert_false(test_address_filtering_aux(0, 0, 1, 0), "");
	/* The remote port is the only one that doesn't matter. */
	success &= assert_true(test_address_filtering_aux(0, 1, 0, 0), "");
	success &= assert_false(test_address_filtering_aux(1, 0, 0, 0), "");

	return true;
}

struct loop_summary {
	struct bib_entry *bib1;
	struct bib_entry *bib2;
};

static int for_each_func(struct bib_entry *entry, void *arg)
{
	struct loop_summary *summary = arg;

	if (summary->bib1 == NULL) {
		summary->bib1 = entry;
		return 0;
	}

	if (summary->bib2 == NULL) {
		summary->bib2 = entry;
		return 0;
	}

	return -EINVAL;
}

static bool test_for_each(void)
{
	struct bib_entry *bib1, *bib2;
	struct loop_summary summary = { .bib1 = NULL, .bib2 = NULL };
	bool success = true;

	bib1 = create_and_insert_bib(0, 0, L4PROTO_UDP);
	if (!bib1)
		return false;
	bib2 = create_and_insert_bib(1, 1, L4PROTO_UDP);
	if (!bib2)
		return false;

	success &= assert_equals_int(0, bib_for_each(L4PROTO_UDP, for_each_func, &summary), "result");
	success &= assert_true(
			bib_entry_equals(bib1, summary.bib1) || bib_entry_equals(bib1, summary.bib2),
			"bib1 visited");
	success &= assert_true(
			bib_entry_equals(bib2, summary.bib1) || bib_entry_equals(bib2, summary.bib2),
			"bib2 visited");

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

	if (is_error(bib_init()))
		return false;

	if (is_error(session_init())) {
		bib_destroy();
		return false;
	}

	return true;
}

static void end(void)
{
	session_destroy();
	bib_destroy();
}

int init_module(void)
{
	START_TESTS("BIB-Session");

	INIT_CALL_END(init(), simple_bib(), end(), "Single BIB");
	INIT_CALL_END(init(), simple_session(), end(), "Single Session");
	INIT_CALL_END(init(), test_address_filtering(), end(), "Address-dependent filtering.");
	INIT_CALL_END(init(), test_for_each(), end(), "for-each function.");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
