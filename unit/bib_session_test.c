#include <linux/module.h>
#include <linux/printk.h>
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#include "nat64/mod/unit_test.h"
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

const char* IPV4_ADDRS[] = { "0.0.0.0", "255.1.2.3", "65.0.123.2", "0.1.0.3",
		"55.55.55.55", "10.11.12.13", "13.12.11.10", "255.255.255.255",
		"1.2.3.4", "4.3.2.1", "2.3.4.5", "5.4.3.2",
		"3.4.5.6", "6.5.4.3", "4.5.6.7", "7.6.5.4",
		"56.56.56.56" };
const __u16 IPV4_PORTS[] = { 0, 456, 9556, 7523,
		65535, 536, 284, 231,
		1234, 4321, 2345, 5432,
		3456, 6543, 4567, 7654,
		6384 };
const char* IPV6_ADDRS[] = { "::1", "5:3::2", "4::", "44:55:66::",
		"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "123::4", "::0", "44:1:1::2:9",
		"1:2:3:4::", "4:3:2:1::", "2:3:4:5::", "5:4:3:2::",
		"3:4:5:6::", "6:5:4:3::", "4:5:6:7::", "7:6:5:4::",
		"56:56:56:56::" };
const __u16 IPV6_PORTS[] = { 334, 0, 9556, 65535,
		55555, 825, 1111, 99,
		1234, 4321, 2345, 5432,
		3456, 6543, 4567, 7654,
		6384 };

struct ipv4_tuple_address addr4[ARRAY_SIZE(IPV4_ADDRS)];
struct ipv6_tuple_address addr6[ARRAY_SIZE(IPV6_ADDRS)];

/********************************************
 * Auxiliar functions.
 ********************************************/

struct bib_entry *create_bib_entry(int ipv4_index, int ipv6_index)
{
	return bib_create(&addr4[ipv4_index], &addr6[ipv6_index], false);
}

struct session_entry *create_session_entry(int remote_id_4, int local_id_4,
		int local_id_6, int remote_id_6,
		struct bib_entry* bib, u_int8_t l4protocol, unsigned int dying_time)
{
	struct ipv4_pair pair_4 = {
			.remote = addr4[remote_id_4],
			.local = addr4[local_id_4],
	};
	struct ipv6_pair pair_6 = {
			.local = addr6[local_id_6],
			.remote = addr6[remote_id_6],
	};

	struct session_entry* entry = session_create(&pair_4, &pair_6, l4protocol);
	if (!entry)
		return NULL;

	entry->dying_time = dying_time;
	if (bib) {
		entry->bib = bib;
		list_add(&entry->entries_from_bib, &bib->sessions);
	}

	return entry;
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
		int remote6_id, struct bib_entry* bib, u_int8_t l4protocol, unsigned int dying_time)
{
	struct session_entry *result;
	int error;

	result = create_session_entry(remote4_id, local4_id, local6_id, remote6_id, bib, l4protocol, dying_time);
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

bool assert_bib_entry_equals(struct bib_entry* expected, struct bib_entry* actual, char* test_name)
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

bool assert_session_entry_equals(struct session_entry* expected, struct session_entry* actual,
		char* test_name)
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
bool assert_bib(char* test_name, struct bib_entry* bib,
		bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
{
	u_int8_t l4protocols[] = { IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP };
	bool table_has_it[] = { udp_table_has_it, tcp_table_has_it, icmp_table_has_it };
	int i;

	for (i = 0; i < 3; i++) {
		struct bib_entry *expected_bib = table_has_it[i] ? bib : NULL;
		struct bib_entry *retrieved_bib;

		retrieved_bib = bib_get_by_ipv4(&bib->ipv4, l4protocols[i]);
		if (!assert_bib_entry_equals(expected_bib, retrieved_bib, test_name))
			return false;

		retrieved_bib = bib_get_by_ipv6(&bib->ipv6, l4protocols[i]);
		if (!assert_bib_entry_equals(expected_bib, retrieved_bib, test_name))
			return false;
	}

	return true;
}

/**
 * Same as assert_bib(), except asserting session entries on the session table.
 */
bool assert_session(char* test_name, struct session_entry* session,
		bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
{
	u_int8_t l4protocols[] = { IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP };
	bool table_has_it[] = { udp_table_has_it, tcp_table_has_it, icmp_table_has_it };
	int i;

	for (i = 0; i < 3; i++) {
		struct ipv4_pair pair_4 = { session->ipv4.remote, session->ipv4.local };
		struct ipv6_pair pair_6 = { session->ipv6.local, session->ipv6.remote };
		struct session_entry *expected_session = table_has_it[i] ? session : NULL;
		struct session_entry *retrieved_session;

		retrieved_session = session_get_by_ipv4(&pair_4, l4protocols[i]);
		if (!assert_session_entry_equals(expected_session, retrieved_session, test_name))
			return false;

		retrieved_session = session_get_by_ipv6(&pair_6, l4protocols[i]);
		if (!assert_session_entry_equals(expected_session, retrieved_session, test_name))
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
bool simple_bib(void)
{
	struct bib_entry *bib;
	bool success = true;

	bib = create_bib_entry(0, 0);
	if (!assert_not_null(bib, "Allocation of test BIB entry"))
		return false;

	success &= assert_equals_int(0, bib_add(bib, IPPROTO_TCP), "BIB insertion call");
	success &= assert_bib("BIB insertion state", bib, false, true, false);
	if (!success)
		/*
		 * Rather have a slight memory leak than corrupted memory. Because of the error, the table
		 * might or might not have a reference to the entry, and if it does, it will try to kfree
		 * it during bib_destroy(). Hence, better not free it here.
		 */
		return false;

	success &= assert_true(bib_remove(bib, IPPROTO_TCP), "BIB removal call");
	success &= assert_bib("BIB removal state", bib, false, false, false);
	if (!success)
		return false;

	kfree(bib);
	return success;
}

bool simple_session(void)
{
	struct session_entry *session;
	bool success = true;

	session = create_session_entry(1, 0, 1, 0, NULL, IPPROTO_TCP, 12345);
	if (!assert_not_null(session, "Allocation of test session entry"))
		return false;

	success &= assert_equals_int(0, session_add(session), "Session insertion call");
	success &= assert_session("Session insertion state", session, false, true, false);
	if (!success)
		return false; /* See simple_bib(). */

	success &= assert_true(session_remove(session), "Session removal call");
	success &= assert_session("Session removal state", session, false, false, false);
	if (!success)
		return false;

	kfree(session);
	return true;
}

#define BIB_COUNT 4
#define SESSIONS_PER_BIB 3

#define ASSERT_SINGLE_BIB(test_name, bib_id, bib_is_alive, s1_is_alive, s2_is_alive, s3_is_alive) \
		assert_bib(test_name, &bibs[bib_id], bib_is_alive, false, false) \
				& assert_session(test_name, &sessions[bib_id][0], s1_is_alive, false, false) \
				& assert_session(test_name, &sessions[bib_id][1], s2_is_alive, false, false) \
				& assert_session(test_name, &sessions[bib_id][2], s3_is_alive, false, false)

/*
 * The following fields are global because they don't fit in test_clean_old_sessions()'s frame
 * size.
 */

/** The BIB entries we inserted to the BIB. */
struct bib_entry *db_bibs[BIB_COUNT];
/** The session entries we inserted to the session tables. */
struct session_entry *db_sessions[BIB_COUNT][SESSIONS_PER_BIB];
/** Copies of db_bibs. We need this because clean_expired_sessions() kfrees the DB entries. */
struct bib_entry bibs[BIB_COUNT];
/** Copies of db_sessions. We need this because clean_expired_sessions() kfrees the DB entries. */
struct session_entry sessions[BIB_COUNT][SESSIONS_PER_BIB];

bool test_clean_old_sessions(void)
{
	int b, s; /* bib counter, session counter. */
	bool success = true;

	const unsigned int before = jiffies_to_msecs(jiffies) - 1000;
	const unsigned int after = jiffies_to_msecs(jiffies) + 1000;

	/* Allocate and insert to the tables. */
	for (b = 0; b < BIB_COUNT; b++) {
		db_bibs[b] = create_and_insert_bib(b, b, IPPROTO_UDP);
		if (!db_bibs[b])
			return false;

		for (s = 0; s < SESSIONS_PER_BIB; s++) {
			db_sessions[b][s] = create_and_insert_session(b, s + 5, b, s + 5, db_bibs[b], IPPROTO_UDP, after);
			if (!db_sessions[b][s])
				return false;

			memcpy(&sessions[b][s], db_sessions[b][s], sizeof(struct session_entry));
		}

		memcpy(&bibs[b], db_bibs[b], sizeof(struct bib_entry));
	}

	db_bibs[3]->is_static = true;

	/* 1. Nothing has expired: Test nothing gets deleted. */
	clean_expired_sessions();

	success &= ASSERT_SINGLE_BIB("Clean deletes nothing", 0, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Clean deletes nothing", 1, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Clean deletes nothing", 2, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Clean deletes nothing", 3, true, true, true, true);

	if (!success)
		return false;

	/* 2. All of a single BIB's sessions expire: Test both BIBs and Sessions die. */
	db_sessions[1][0]->dying_time = before;
	db_sessions[1][1]->dying_time = before;
	db_sessions[1][2]->dying_time = before;

	clean_expired_sessions();

	success &= ASSERT_SINGLE_BIB("Whole BIB dies 0", 0, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Whole BIB dies 1", 1, false, false, false, false);
	success &= ASSERT_SINGLE_BIB("Whole BIB dies 2", 2, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Whole BIB dies 3", 3, true, true, true, true);

	if (!success)
		return false;

	/* 3. Some sessions of a BIB expire: Test only those sessions get deleted. */
	db_sessions[2][0]->dying_time = before;
	db_sessions[2][1]->dying_time = before;

	clean_expired_sessions();

	success &= ASSERT_SINGLE_BIB("Some sessions die", 0, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Some sessions die", 1, false, false, false, false);
	success &= ASSERT_SINGLE_BIB("Some sessions die", 2, true, false, false, true);
	success &= ASSERT_SINGLE_BIB("Some sessions die", 3, true, true, true, true);

	if (!success)
		return false;

	/* 4. The rest of them expire: Test the BIB keeps keeps behaving as expected. */
	db_sessions[2][2]->dying_time = before;

	clean_expired_sessions();

	success &= ASSERT_SINGLE_BIB("Last session dies", 0, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Last session dies", 1, false, false, false, false);
	success &= ASSERT_SINGLE_BIB("Last session dies", 2, false, false, false, false);
	success &= ASSERT_SINGLE_BIB("Last session dies", 3, true, true, true, true);

	if (!success)
		return false;

	/* 5. The sessions of a static BIB expire. Test only the sessions ones die. */
	db_sessions[3][0]->dying_time = before;
	db_sessions[3][1]->dying_time = before;
	db_sessions[3][2]->dying_time = before;

	clean_expired_sessions();

	success &= ASSERT_SINGLE_BIB("Static session doesn't die", 0, true, true, true, true);
	success &= ASSERT_SINGLE_BIB("Static session doesn't die", 1, false, false, false, false);
	success &= ASSERT_SINGLE_BIB("Static session doesn't die", 2, false, false, false, false);
	success &= ASSERT_SINGLE_BIB("Static session doesn't die", 3, true, false, false, false);

	/* Quit. */
	return success;
}

#undef BIB_COUNT
#undef SESSIONS_PER_BIB
#undef ASSERT_SINGLE_BIB

static bool test_address_filtering_aux(int src_addr_id, int src_port_id, int dst_addr_id,
		int dst_port_id)
{
	struct tuple tuple;

	tuple.src.addr.ipv4 = addr4[src_addr_id].address;
	tuple.dst.addr.ipv4 = addr4[dst_addr_id].address;
	tuple.src.l4_id = IPV4_PORTS[src_port_id];
	tuple.dst.l4_id = IPV4_PORTS[dst_port_id];
	tuple.l4_proto = IPPROTO_UDP;
	tuple.l3_proto 	= PF_INET;

	return session_allow(&tuple);
}

bool test_address_filtering(void)
{
	struct bib_entry *bib;
	struct session_entry *session;
	bool success = true;

	/* Init. */
	bib = create_and_insert_bib(0, 0, IPPROTO_UDP);
	if (!bib)
		return false;
	session = create_and_insert_session(0, 0, 0, 0, bib, IPPROTO_UDP, 12345);
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

int for_each_func(struct bib_entry *entry, void *arg)
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

bool test_for_each(void)
{
	struct bib_entry *bib1, *bib2;
	struct loop_summary summary = { .bib1 = NULL, .bib2 = NULL };
	bool success = true;

	bib1 = create_and_insert_bib(0, 0, IPPROTO_UDP);
	if (!bib1)
		return false;
	bib2 = create_and_insert_bib(1, 1, IPPROTO_UDP);
	if (!bib2)
		return false;

	success &= assert_equals_int(0, bib_for_each(IPPROTO_UDP, for_each_func, &summary), "");
	success &= assert_true(bib_entry_equals(bib1, summary.bib1) || bib_entry_equals(bib1, summary.bib2), "");
	success &= assert_true(bib_entry_equals(bib2, summary.bib2) || bib_entry_equals(bib2, summary.bib2), "");

	return success;
}

/********************************************
 * Main.
 ********************************************/

static bool session_always_dies(struct session_entry *session)
{
	return false;
}

bool init(void)
{
	int error;
	int i;

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		error = str_to_addr4(IPV4_ADDRS[i], &addr4[i].address);
		if (error)
			return false;
		addr4[i].l4_id = IPV4_PORTS[i];
	}

	for (i = 0; i < ARRAY_SIZE(IPV4_ADDRS); i++) {
		error = str_to_addr6(IPV6_ADDRS[i], &addr6[i].address);
		if (error)
			return false;
		addr6[i].l4_id = IPV6_PORTS[i];
	}

	error = bib_init();
	if (error)
		return false;

	error = session_init(session_always_dies);
	if (error) {
		bib_destroy();
		return false;
	}

	return true;
}

void end(void)
{
	session_destroy();
	bib_destroy();
}

int init_module(void)
{
	START_TESTS("BIB-Session");

	INIT_CALL_END(init(), simple_bib(), end(), "Single BIB");
	INIT_CALL_END(init(), simple_session(), end(), "Single Session");
	INIT_CALL_END(init(), test_clean_old_sessions(), end(), "Session cleansing.");
	INIT_CALL_END(init(), test_address_filtering(), end(), "Address-dependent filtering.");
	INIT_CALL_END(init(), test_for_each(), end(), "for-each function.");

	END_TESTS;
}

void cleanup_module(void)
{
	// Sin codigo.
}
