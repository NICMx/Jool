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

const char* IPV4_ADDRS[] = { "0.0.0.0", "255.1.2.3", "65.0.123.2", "0.1.0.3", //
		"55.55.55.55", "10.11.12.13", "13.12.11.10", "255.255.255.255", //
		"1.2.3.4", "4.3.2.1", "2.3.4.5", "5.4.3.2", //
		"3.4.5.6", "6.5.4.3", "4.5.6.7", "7.6.5.4", //
		"56.56.56.56" };
const __u16 IPV4_PORTS[] = { 0, 456, 9556, 7523, //
		65535, 536, 284, 231, //
		1234, 4321, 2345, 5432, //
		3456, 6543, 4567, 7654, //
		6384 };
const char* IPV6_ADDRS[] = { "::1", "5:3::2", "4::", "44:55:66::", //
		"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "123::4", "::0", "44:1:1::2:9", //
		"1:2:3:4::", "4:3:2:1::", "2:3:4:5::", "5:4:3:2::", //
		"3:4:5:6::", "6:5:4:3::", "4:5:6:7::", "7:6:5:4::", //
		"56:56:56:56::" };
const __u16 IPV6_PORTS[] = { 334, 0, 9556, 65535, //
		55555, 825, 1111, 99, //
		1234, 4321, 2345, 5432, //
		3456, 6543, 4567, 7654, //
		6384 };

/********************************************
 * Auxiliar functions.
 ********************************************/

struct ipv4_tuple_address create_tuple_addr_4(int index)
{
	struct ipv4_tuple_address result;
	if (str_to_addr4(IPV4_ADDRS[index], &result.address) != ERR_SUCCESS)
		log_warning("Can't convert '%s' to a in_addr. Test is going to fail.", IPV4_ADDRS[index]);
	result.l4_id = IPV4_PORTS[index];
	return result;
}

struct ipv6_tuple_address create_tuple_addr_6(int index)
{
	struct ipv6_tuple_address result;
	if (str_to_addr6(IPV6_ADDRS[index], &result.address) != ERR_SUCCESS)
		log_warning("Can't convert '%s' to a in6_addr. Test is going to fail.", IPV6_ADDRS[index]);
	result.l4_id = IPV6_PORTS[index];
	return result;
}

struct bib_entry *create_bib_entry(int ipv4_index, int ipv6_index)
{
	struct ipv4_tuple_address address_4 = create_tuple_addr_4(ipv4_index);
	struct ipv6_tuple_address address_6 = create_tuple_addr_6(ipv4_index);
	return bib_create(&address_4, &address_6);
}

struct session_entry *create_session_entry(
		int remote_id_4, int local_id_4, int local_id_6, int remote_id_6,
		struct bib_entry* bib, u_int8_t l4protocol, unsigned int dying_time)
{
	struct ipv4_pair pair_4 = { create_tuple_addr_4(remote_id_4), create_tuple_addr_4(local_id_4) };
	struct ipv6_pair pair_6 = { create_tuple_addr_6(local_id_6), create_tuple_addr_6(remote_id_6) };

	struct session_entry* entry = session_create_static(&pair_4, &pair_6, bib,
			l4protocol);
	if (!entry) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate a session entry.");
		return NULL;
	}

	entry->is_static = false;
	entry->dying_time = dying_time;

	return entry;
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

	// Init
	bib = create_bib_entry(0, 0);
	if (!bib) {
		log_warning("Could not allocate a BIB entry.");
		return false;
	}

	// Add
	if (bib_add(bib, IPPROTO_TCP) != ERR_SUCCESS) {
		log_warning("Test 'BIB insertion' failed: Call returned failure.");
		return false;
	}
	if (!assert_bib("BIB insertion", bib, false, true, false))
		return false;

	// Remove
	if (!bib_remove(bib, IPPROTO_TCP)) {
		log_warning("Test 'BIB removal' failed: Call returned false.");
		return false;
	}
	if (!assert_bib("BIB removal", bib, false, false, false))
		return false;

	// Quit
	return true;
}

bool simple_bib_session(void)
{
	struct bib_entry *bib;
	struct session_entry *session;

	bib = create_bib_entry(0, 0);
	if (!bib) {
		log_warning("Could not allocate a BIB entry.");
		return false;
	}
	session = create_session_entry(1, 0, 1, 0, bib, IPPROTO_TCP, 12345);
	if (!session) {
		log_warning("Could not allocate a Session entry.");
		return false;
	}

	// Insert the BIB entry.
	if (bib_add(bib, IPPROTO_TCP) != ERR_SUCCESS) {
		log_warning("Test 'BIB insertion' failed: Call returned failure.");
		return false;
	}
	if (!assert_bib("BIB insertion", bib, false, true, false))
		return false;

	// Insert the session entry.
	if (session_add(session) != ERR_SUCCESS) {
		log_warning("Test 'Session insertion' failed: Call returned failure.");
		return false;
	}
	if (!assert_session("Session insertion", session, false, true, false))
		return false;

	// The BIB entry has a session entry, so it shouldn't be removable.
	if (bib_remove(bib, IPPROTO_TCP)) {
		log_warning("Test 'Bib removal' failed: Removal shouldn't have succeeded.");
		return false;
	}
	if (!assert_bib("Bib removal (bib table)", bib, false, true, false))
		return false;
	if (!assert_session("BIB removal (session table)", session, false, true, false))
		return false;

	// Remove the session entry.
	// Because the BIB entry no longer has sessions, it should be automatically removed as well.
	if (!session_remove(session)) {
		log_warning("Test 'Session removal' failed: Call returned false.");
		return false;
	}
	if (!assert_bib("Session removal (bib table)", bib, false, false, false))
		return false;
	if (!assert_session("Session removal (session table)", session, false, false, false))
		return false;

	// Quit.
	return true;
}

#define BIB_COUNT 4
#define SESSIONS_PER_BIB 3

#define ASSERT_SINGLE_BIB(test_name, bib_id, bib_is_alive, s1_is_alive, s2_is_alive, s3_is_alive) \
	if (!assert_bib(test_name, bibs[bib_id], bib_is_alive, false, false)) return false; \
	if (!assert_session(test_name, sessions[bib_id][0], s1_is_alive, false, false)) return false; \
	if (!assert_session(test_name, sessions[bib_id][1], s2_is_alive, false, false)) return false; \
	if (!assert_session(test_name, sessions[bib_id][2], s3_is_alive, false, false)) return false;

bool test_clean_old_sessions(void)
{
	struct bib_entry *bibs[BIB_COUNT];
	struct session_entry *sessions[BIB_COUNT][SESSIONS_PER_BIB];
	int cbib, cses; // "BIB counter, session counter". Sorry; I use them too much.

	const unsigned int time_before = jiffies_to_msecs(jiffies) - 1000;
	const unsigned int time_after = jiffies_to_msecs(jiffies) + 1000;

	// Allocate.
	for (cbib = 0; cbib < BIB_COUNT; cbib++) {
		bibs[cbib] = create_bib_entry(cbib, cbib);
		if (!bibs[cbib]) {
			log_warning("Could not allocate a BIB entry %d.", cbib);
			return false;
		}
	}

	for (cbib = 0; cbib < BIB_COUNT; cbib++) {
		for (cses = 0; cses < SESSIONS_PER_BIB; cses++) {
			sessions[cbib][cses] = create_session_entry(cbib, cses + 5, cbib, cses + 5,
					bibs[cbib], IPPROTO_UDP, time_after);
			if (!sessions[cbib][cses]) {
				log_warning("Could not allocate a Session entry %d-%d.", cbib, cses);
				return false;
			}
		}
	}

	sessions[3][1]->is_static = true;

	// Insert to the tables.
	for (cbib = 0; cbib < BIB_COUNT; cbib++) {
		if (bib_add(bibs[cbib], IPPROTO_UDP) != ERR_SUCCESS) {
			log_warning("Could not add BIB entry %d.", cbib);
			return false;
		}
	}

	for (cbib = 0; cbib < BIB_COUNT; cbib++) {
		for (cses = 0; cses < SESSIONS_PER_BIB; cses++) {
			if (session_add(sessions[cbib][cses]) != ERR_SUCCESS) {
				log_warning("Could not add session entry %d-%d.", cbib, cses);
				return false;
			}
		}
	}

	// 1. Nothing has expired:
	// Test nothing gets deleted.
	clean_expired_sessions();

	ASSERT_SINGLE_BIB("Clean deletes nothing", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Clean deletes nothing", 1, true, true, true, true);
	ASSERT_SINGLE_BIB("Clean deletes nothing", 2, true, true, true, true);
	ASSERT_SINGLE_BIB("Clean deletes nothing", 3, true, true, true, true);

	// 2. All of a single BIB's sessions expire:
	// Test both BIBs and Sessions die.
	sessions[1][0]->dying_time = time_before;
	sessions[1][1]->dying_time = time_before;
	sessions[1][2]->dying_time = time_before;

	clean_expired_sessions();

	ASSERT_SINGLE_BIB("Whole BIB dies", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Whole BIB dies", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Whole BIB dies", 2, true, true, true, true);
	ASSERT_SINGLE_BIB("Whole BIB dies", 3, true, true, true, true);

	// 3. Some sessions of a BIB expire:
	// Test only they get deleted.
	sessions[2][0]->dying_time = time_before;
	sessions[2][1]->dying_time = time_before;

	clean_expired_sessions();

	ASSERT_SINGLE_BIB("Some sessions die", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Some sessions die", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Some sessions die", 2, true, false, false, true);
	ASSERT_SINGLE_BIB("Some sessions die", 3, true, true, true, true);

	// 4. The rest of them expire:
	// Test the BIB keeps keeps behaving as expected. Perhaps unnecesary.
	sessions[2][2]->dying_time = time_before;

	clean_expired_sessions();

	ASSERT_SINGLE_BIB("Last session dies", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Last session dies", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Last session dies", 2, false, false, false, false);
	ASSERT_SINGLE_BIB("Last session dies", 3, true, true, true, true);

	// 5. The sessions of a static BIB expire, but one of them is static.
	// Test only the dynamic ones die.
	sessions[3][0]->dying_time = time_before;
	sessions[3][1]->dying_time = time_before;
	sessions[3][2]->dying_time = time_before;

	clean_expired_sessions();

	ASSERT_SINGLE_BIB("Static session doesn't die", 0, true, true, true, true);
	ASSERT_SINGLE_BIB("Static session doesn't die", 1, false, false, false, false);
	ASSERT_SINGLE_BIB("Static session doesn't die", 2, false, false, false, false);
	ASSERT_SINGLE_BIB("Static session doesn't die", 3, true, false, true, false);

	// Quit.
	return true;
}

#undef BIB_COUNT
#undef SESSIONS_PER_BIB
#undef ASSERT_SINGLE_BIB

bool test_address_filtering_aux(int src_addr_id, int src_port_id, int dst_addr_id, int dst_port_id,
		bool expected)
{
	struct tuple tuple;

	if (str_to_addr4(IPV4_ADDRS[src_addr_id], &tuple.src.addr.ipv4) != ERR_SUCCESS) {
		log_warning("Can't parse the '%s' source address. Failing test.", IPV4_ADDRS[src_addr_id]);
		return false;
	}
	if (str_to_addr4(IPV4_ADDRS[dst_addr_id], &tuple.dst.addr.ipv4) != ERR_SUCCESS) {
		log_warning("Can't parse the '%s' dest address. Failing test.", IPV4_ADDRS[dst_addr_id]);
		return false;
	}
	tuple.src.l4_id = IPV4_PORTS[src_port_id];
	tuple.dst.l4_id = IPV4_PORTS[dst_port_id];
	tuple.l4_proto = IPPROTO_UDP;
	tuple.l3_proto 	= PF_INET;

	return (expected == session_allow(&tuple));
}

bool test_address_filtering(void)
{
	struct bib_entry *bib;
	struct session_entry *session;

	// Init.
	bib = create_bib_entry(0, 0);
	if (!bib) {
		log_warning("Could not allocate a BIB entry.");
		return false;
	}
	session = create_session_entry(0, 0, 0, 0, bib, IPPROTO_UDP, 12345);
	if (!session) {
		log_warning("Could not allocate a Session entry.");
		return false;
	}

	if (bib_add(bib, IPPROTO_UDP) != ERR_SUCCESS) {
		log_warning("Could not add the BIB entry.");
		return false;
	}
	if (session_add(session) != ERR_SUCCESS) {
		log_warning("Could not add the session entry.");
		return false;
	}

	// Test the packet is allowed when the tuple and session match perfectly.
	if (!test_address_filtering_aux(0, 0, 0, 0, true))
		return false;

	// Test a tuple that completely mismatches the session.
	if (!test_address_filtering_aux(1, 1, 1, 1, false))
		return false;

	// Now test tuples that nearly match the session.
	if (!test_address_filtering_aux(0, 0, 0, 1, false))
		return false;
	if (!test_address_filtering_aux(0, 0, 1, 0, false))
		return false;
	if (!test_address_filtering_aux(0, 1, 0, 0, true))
		return false; // The remote port is the only one that doesn't matter.
	if (!test_address_filtering_aux(1, 0, 0, 0, false))
		return false;

	return true;
}

bool test_to_array(void)
{
	struct bib_entry *first_bib, *second_bib;
	struct bib_entry **array;
	int array_size;

	// Create and insert BIBs.
	first_bib = create_bib_entry(0, 0);
	if (!first_bib) {
		log_warning("Could not allocate the first BIB entry.");
		return false;
	}
	if (bib_add(first_bib, IPPROTO_UDP) != ERR_SUCCESS) {
		log_warning("Could not add the first BIB entry.");
		return false;
	}

	second_bib = create_bib_entry(1, 1);
	if (!second_bib) {
		log_warning("Could not allocate the second BIB entry.");
		return false;
	}
	if (bib_add(second_bib, IPPROTO_UDP) != ERR_SUCCESS) {
		log_warning("Could not add the second BIB entry.");
		return false;
	}

	// Call the function.
	array_size = bib_to_array(IPPROTO_UDP, &array);

	// Return value validations.
	if (array_size == -1) {
		log_warning("bib_to_array could not allocate the array.");
		goto free;
	}
	if (array_size != 2) {
		log_warning("Inserted 2 bibs, but the resulting array length is %d.", array_size);
		goto free;
	}

	// Array content validations.
	if (!bib_entry_equals(first_bib, array[0]) && !bib_entry_equals(first_bib, array[1])) {
		log_warning("The result array does not contain the first BIB entry.");
		goto free;
	}
	if (!bib_entry_equals(second_bib, array[0]) && !bib_entry_equals(second_bib, array[1])) {
		log_warning("The result array does not contain the second BIB entry.");
		goto free;
	}

	kfree(array);
	return true;

free:
	kfree(array);
	return false;
}

/********************************************
 * Main.
 ********************************************/

bool init(void)
{
	return bib_init() && session_init();
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
	INIT_CALL_END(init(), simple_bib_session(), end(), "Single BIB-Session");
	INIT_CALL_END(init(), test_clean_old_sessions(), end(), "Session cleansing.");
	INIT_CALL_END(init(), test_address_filtering(), end(), "Address-dependent filtering.");
	INIT_CALL_END(init(), test_to_array(), end(), "To array function.");

	END_TESTS;
}

void cleanup_module(void)
{
	// Sin codigo.
}
