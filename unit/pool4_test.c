#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "pool4.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("IPv4 pool module test");


#define ID_COUNT				65536
#define PORT_LOW_RANGE_MAX		1023
#define PORT_HIGH_RANGE_MAX		(ID_COUNT - 1)
#define ICMP_ID_MAX				(ID_COUNT - 1)

char* expected_ips_as_str[] = { "192.168.2.1", "192.168.2.2" };
struct in_addr expected_ips[ARRAY_SIZE(expected_ips_as_str)];
/**
 * This is used by the tests.
 * It's too big for the stack frame limit, and I don't feel like meddling with kmallocs,
 * so here it is.
 *
 * If true, ports[n][m] indicates that port m of the nth address has been retrieved from the
 * pool. If false, it means that the pool has it.
 */
static bool ports[ARRAY_SIZE(expected_ips)][ID_COUNT];

static bool test_get_any_aux(enum l4_protocol l4_proto, u32 port_min, u32 port_max, u32 step, char *test_name)
{
	u32 addr_ctr, port_ctr;
	struct ipv4_tuple_address result;
	bool success = true;

	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		for (port_ctr = port_min; port_ctr <= port_max; port_ctr += step) {
			success &= assert_true(pool4_get_any(l4protocol, port_ctr, &result), test_name);
			success &= assert_equals_ipv4(&expected_ips[addr_ctr], &result.address, test_name);
			success &= assert_false(ports[addr_ctr][result.l4_id], test_name);
			ports[addr_ctr][result.l4_id] = true;
		}
	}
	success &= assert_false(pool4_get_any(l4protocol, 0, &result), test_name);

	return success;
}

/**
 * The get_any function cannot be fully tested on its own, so the basics are here and some more
 * hacking is done in test_return_function().
 *
 * Tests to some extent that the different ranges do not interfere with each other during gets.
 */
static bool test_get_any_function_udp(void)
{
	bool success = true;

	success &= test_get_any_aux(L4PROTO_UDP, 0, PORT_LOW_RANGE_MAX, 2, "UDP-Low even ports");
	success &= test_get_any_aux(L4PROTO_UDP, 1, PORT_LOW_RANGE_MAX, 2, "UDP-Low odd ports");
	success &= test_get_any_aux(L4PROTO_UDP, 1024, PORT_HIGH_RANGE_MAX, 2, "UDP-High even ports");
	success &= test_get_any_aux(L4PROTO_UDP, 1025, PORT_HIGH_RANGE_MAX, 2, "UDP-High odd ports");

	return success;
}

static bool test_get_any_function_tcp(void)
{
	bool success = true;

	success &= test_get_any_aux(L4PROTO_TCP, 0, PORT_LOW_RANGE_MAX, 1, "TCP-Low ports");
	success &= test_get_any_aux(L4PROTO_TCP, 1024, PORT_HIGH_RANGE_MAX, 1, "TCP-High ports");

	return success;
}

static bool test_get_any_function_icmp(void)
{
	return test_get_any_aux(L4PROTO_ICMP, 0, ICMP_ID_MAX, 1, "ICMP-ids");
}

static bool test_get_similar_aux(enum l4_protocol l4_proto, u32 port_min, u32 port_max, u32 step, char *test_name)
{
	u32 addr_ctr, port_ctr;
	struct ipv4_tuple_address query, result;
	bool success = true;

	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		query.address = expected_ips[addr_ctr];

		for (port_ctr = port_min; port_ctr <= port_max; port_ctr += step) {
			query.l4_id = port_ctr;
			success &= assert_true(pool4_get_similar(l4protocol, &query, &result), test_name);
			success &= assert_equals_ipv4(&expected_ips[addr_ctr], &result.address, test_name);
			success &= assert_false(ports[addr_ctr][result.l4_id], test_name);
			ports[addr_ctr][result.l4_id] = true;
		}

		query.l4_id = port_min;
		success &= assert_false(pool4_get_similar(l4protocol, &query, &result), test_name);
	}

	return success;
}

static bool test_get_similar_function_udp(void)
{
	bool success = true;

	success &= test_get_similar_aux(L4PROTO_UDP, 0, PORT_LOW_RANGE_MAX, 2, "UDP-Low even ports");
	success &= test_get_similar_aux(L4PROTO_UDP, 1, PORT_LOW_RANGE_MAX, 2, "UDP-Low odd ports");
	success &= test_get_similar_aux(L4PROTO_UDP, 1024, PORT_HIGH_RANGE_MAX, 2, "UDP-High even ports");
	success &= test_get_similar_aux(L4PROTO_UDP, 1025, PORT_HIGH_RANGE_MAX, 2, "UDP-High odd ports");

	return success;
}

static bool test_get_similar_function_tcp(void)
{
	bool success = true;

	success &= test_get_similar_aux(L4PROTO_TCP, 0, PORT_LOW_RANGE_MAX, 1, "TCP-Low even ports");
	success &= test_get_similar_aux(L4PROTO_TCP, 1024, PORT_HIGH_RANGE_MAX, 1, "TCP-High odd ports");

	return success;
}

static bool test_get_similar_function_icmp(void)
{
	return test_get_similar_aux(L4PROTO_ICMP, 0, ICMP_ID_MAX, 1, "ICMP-ids");
}

/**
 * Only UDP and its lower even range of ports is tested here.
 */
static bool test_return_function(void)
{
	struct ipv4_tuple_address query, result;
	bool success = true;
	int addr_ctr, port_ctr;

	/* Try to return the entire pool, even though we haven't borrowed anything. */
	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		result.address = expected_ips[addr_ctr];
		for (port_ctr = 0; port_ctr < 1024; port_ctr += 2) {
			result.l4_id = port_ctr;
			success &= assert_false(pool4_return(L4PROTO_UDP, &result), "");
		}
	}

	/* Borrow the entire pool. */
	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		for (port_ctr = 0; port_ctr < 1024; port_ctr += 2) {
			success &= assert_true(pool4_get_any(L4PROTO_UDP, port_ctr, &result), "Borrow-result");
			success &= assert_equals_ipv4(&expected_ips[addr_ctr], &result.address, "Borrow-addr");
			success &= assert_false(ports[addr_ctr][result.l4_id], "Borrow-port");
			ports[addr_ctr][result.l4_id] = true;
		}
	}
	success &= assert_false(pool4_get_any(L4PROTO_UDP, 0, &result), "Pool should be exhausted.");

	if (!success)
		return success;

	/* Return something from the first address. */
	result.address = expected_ips[0];
	result.l4_id = 1000;
	success &= assert_true(pool4_return(L4PROTO_UDP, &result), "Return");
	ports[0][result.l4_id] = false;

	if (!success)
		return success;

	/* Re-borrow it, assert it's the same one. */
	success &= assert_true(pool4_get_any(L4PROTO_UDP, 0, &result), "");
	success &= assert_equals_ipv4(&expected_ips[0], &result.address, "");
	success &= assert_false(ports[0][result.l4_id], "");
	ports[0][result.l4_id] = true;
	success &= assert_false(pool4_get_any(L4PROTO_UDP, 0, &result), "");

	if (!success)
		return success;

	/*
	 * Do the same to the second address. Use get_similar() instead of get_any() to add some quick
	 * noise.
	 */
	result.address = expected_ips[1];
	result.l4_id = 1000;
	success &= assert_true(pool4_return(L4PROTO_UDP, &result), "Return");
	ports[1][result.l4_id] = false;

	if (!success)
		return success;

	query.address = expected_ips[1];
	query.l4_id = 0;
	success &= assert_true(pool4_get_similar(L4PROTO_UDP, &query, &result), "");
	success &= assert_equals_ipv4(&expected_ips[1], &result.address, "");
	success &= assert_false(ports[1][result.l4_id], "");
	ports[1][result.l4_id] = true;
	success &= assert_false(pool4_get_similar(L4PROTO_UDP, &query, &result), "");

	if (!success)
		return success;

	/* Return some more stuff at once. */
	result.address = expected_ips[0];
	result.l4_id = 46;
	success &= assert_true(pool4_return(L4PROTO_UDP, &result), "Return Addr1-port46");
	ports[0][46] = false;

	result.l4_id = 1000;
	success &= assert_true(pool4_return(L4PROTO_UDP, &result), "Return Addr1-port1000");
	ports[0][1000] = false;

	result.address = expected_ips[1];
	result.l4_id = 0;
	success &= assert_true(pool4_return(L4PROTO_UDP, &result), "ReReturn Addr2-port0");
	ports[1][0] = false;

	if (!success)
		return success;

	/* Reborrow it. */
	success &= assert_true(pool4_get_any(L4PROTO_UDP, 24, &result), "Reborrow Addr1-res-port24");
	success &= assert_equals_ipv4(&expected_ips[0], &result.address, "");
	success &= assert_false(ports[0][result.l4_id], "");
	ports[0][result.l4_id] = true;

	query.address = expected_ips[0];
	query.l4_id = 100;
	success &= assert_true(pool4_get_similar(L4PROTO_UDP, &query, &result), "Reborrow Addr1-res-port100");
	success &= assert_equals_ipv4(&expected_ips[0], &result.address, "");
	success &= assert_false(ports[0][result.l4_id], "");
	ports[0][result.l4_id] = true;

	success &= assert_true(pool4_get_any(L4PROTO_UDP, 56, &result), "ReReborrow Addr2-res-port56");
	success &= assert_equals_ipv4(&expected_ips[1], &result.address, "");
	success &= assert_false(ports[1][result.l4_id], "");
	ports[1][result.l4_id] = true;

	success &= assert_false(pool4_get_any(L4PROTO_UDP, 12, &result), "");

	if (!success)
		return success;

	/* Now return everything. */
	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		result.address = expected_ips[addr_ctr];
		for (port_ctr = 0; port_ctr < 1024; port_ctr += 2) {
			result.l4_id = port_ctr;
			success &= assert_true(pool4_return(L4PROTO_UDP, &result), "");
			ports[addr_ctr][port_ctr] = false;
		}
	}
	success &= assert_false(pool4_return(L4PROTO_UDP, &result), "");

	return success;
}

static bool init(void)
{
	int addr_ctr, port_ctr;

	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		if (str_to_addr4(expected_ips_as_str[addr_ctr], &expected_ips[addr_ctr]) != 0) {
			log_warning("Cannot parse test address '%s'. Failing.", expected_ips_as_str[addr_ctr]);
			return false;
		}
	}

	if (pool4_init(expected_ips_as_str, ARRAY_SIZE(expected_ips_as_str)) != 0) {
		log_warning("Could not init the pool. Failing...");
		return false;
	}

	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++)
		for (port_ctr = 0; port_ctr < ID_COUNT; port_ctr++)
			ports[addr_ctr][port_ctr] = false;

	return true;
}

static void destroy(void)
{
	pool4_destroy();
}

int init_module(void)
{
	START_TESTS("Pool");

	INIT_CALL_END(init(), test_get_any_function_udp(), destroy(), "Get simple-UDP");
	INIT_CALL_END(init(), test_get_any_function_tcp(), destroy(), "Get simple-TCP");
	INIT_CALL_END(init(), test_get_any_function_icmp(), destroy(), "Get simple-ICMP");
	INIT_CALL_END(init(), test_get_similar_function_udp(), destroy(), "Get similar-UDP");
	INIT_CALL_END(init(), test_get_similar_function_tcp(), destroy(), "Get similar-TCP");
	INIT_CALL_END(init(), test_get_similar_function_icmp(), destroy(), "Get similar-ICMP");
	INIT_CALL_END(init(), test_return_function(), destroy(), "Return function");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
