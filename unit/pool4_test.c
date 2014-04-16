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

static char* expected_ips_as_str[] = { "192.168.2.1", "192.168.2.2" };
static struct in_addr expected_ips[ARRAY_SIZE(expected_ips_as_str)];
/**
 * This is used by the tests.
 * It's too big for the stack frame limit, and I don't feel like meddling with kmallocs,
 * so here it is.
 *
 * If true, ports[n][m] indicates that port m of the nth address has been retrieved from the
 * pool. If false, it means that the pool has it.
 */
static bool ports[ARRAY_SIZE(expected_ips)][ID_COUNT];

static bool test_get_match_aux(enum l4_protocol proto, int port_min, int port_max, int step,
		char *test_name)
{
	int a, p; /* address counter, port counter */
	struct ipv4_tuple_address base;
	__u16 result;
	bool success = true;

	for (a = 0; a < ARRAY_SIZE(expected_ips); a++) {
		base.address = expected_ips[a];

		for (p = port_min; p <= port_max; p += step) {
			base.l4_id = p;
			success &= assert_equals_int(0, pool4_get_match(proto, &base, &result), test_name);
			success &= assert_false(ports[a][result], test_name);
			ports[a][result] = true;

			if (!success)
				return false;
		}

		if (!assert_equals_int(-ESRCH, pool4_get_match(proto, &base, &result), test_name))
			return false;
	}

	return true;
}

/**
 * The get_any function cannot be fully tested on its own, so the basics are here and some more
 * hacking is done in test_return_function().
 *
 * Tests to some extent that the different ranges do not interfere with each other during gets.
 */
static bool test_get_match_function_udp(void)
{
	bool success = true;

	success &= test_get_match_aux(L4PROTO_UDP, 0, PORT_LOW_RANGE_MAX, 2, "UDP-Low even ports");
	success &= test_get_match_aux(L4PROTO_UDP, 1, PORT_LOW_RANGE_MAX, 2, "UDP-Low odd ports");
	success &= test_get_match_aux(L4PROTO_UDP, 1024, PORT_HIGH_RANGE_MAX, 2, "UDP-High even ports");
	success &= test_get_match_aux(L4PROTO_UDP, 1025, PORT_HIGH_RANGE_MAX, 2, "UDP-High odd ports");

	return success;
}

static bool test_get_match_function_tcp(void)
{
	bool success = true;

	success &= test_get_match_aux(L4PROTO_TCP, 0, PORT_LOW_RANGE_MAX, 1, "TCP-Low ports");
	success &= test_get_match_aux(L4PROTO_TCP, 1024, PORT_HIGH_RANGE_MAX, 1, "TCP-High ports");

	return success;
}

static bool test_get_match_function_icmp(void)
{
	return test_get_match_aux(L4PROTO_ICMP, 0, ICMP_ID_MAX, 1, "ICMP-ids");
}

static bool test_get_any_port_aux(enum l4_protocol proto, char *test_name)
{
	int a, p; /* address counter, port counter */
	__u16 result;
	bool success = true;

	for (a = 0; a < ARRAY_SIZE(expected_ips); a++) {
		for (p = 0; p < ID_COUNT; p++) {
			success &= assert_equals_int(0, pool4_get_any_port(proto, &expected_ips[a], &result),
					test_name);
			success &= assert_false(ports[a][result], test_name);
			ports[a][result] = true;

			if (!success)
				return success;
		}

		if (!assert_equals_int(-ESRCH, pool4_get_any_port(proto, &expected_ips[a], &result),
				test_name))
			return false;
	}

	return true;
}

static bool test_get_any_port_function_udp(void)
{
	return test_get_any_port_aux(L4PROTO_UDP, "UDP ports");
}

static bool test_get_any_port_function_tcp(void)
{
	return test_get_any_port_aux(L4PROTO_TCP, "TCP ports");
}

static bool test_get_any_port_function_icmp(void)
{
	return test_get_any_port_aux(L4PROTO_ICMP, "ICMP-ids");
}

static bool test_get_any_addr_aux(l4_protocol proto, int min_range, int max_range, int range_step,
		int range_outside)
{
	struct ipv4_tuple_address tuple_addr;
	int p;
	bool success = true;

	for (p = min_range; p <= max_range; p += range_step) {
		success &= assert_equals_int(0, pool4_get_any_addr(proto, p, &tuple_addr),
				"Matched borrow 1-result");
		success &= assert_equals_ipv4(&expected_ips[0], &tuple_addr.address,
				"Matched borrow 1-address");
		success &= assert_false(ports[0][tuple_addr.l4_id], "Matched borrow 1-port");
		ports[0][tuple_addr.l4_id] = true;

		success &= assert_equals_int(0, pool4_get_any_addr(proto, p, &tuple_addr),
				"Matched borrow 2-result");
		success &= assert_equals_ipv4(&expected_ips[1], &tuple_addr.address,
				"Matched borrow 2-address");
		success &= assert_false(ports[1][tuple_addr.l4_id], "Matched borrow 2-port");
		ports[1][tuple_addr.l4_id] = true;

		if (!success)
			return success;
	}

	/* At this point, the pool should not have low even ports, so it should lend random data. */
	for (p = 0; p <= range_outside; p += 1) {
		success &= assert_equals_int(0, pool4_get_any_addr(proto, 10, &tuple_addr),
				"Mismatched borrow 1-result");
		success &= assert_equals_ipv4(&expected_ips[0], &tuple_addr.address,
				"Mismatched borrow 1-address");
		success &= assert_false(ports[0][tuple_addr.l4_id], "Mismatched borrow 1-port");
		ports[0][tuple_addr.l4_id] = true;

		success &= assert_equals_int(0, pool4_get_any_addr(proto, 10, &tuple_addr),
				"Mismatched borrow 2-result");
		success &= assert_equals_ipv4(&expected_ips[1], &tuple_addr.address,
				"Mismatched borrow 2-address");
		success &= assert_false(ports[1][tuple_addr.l4_id], "Mismatched borrow 2-port");
		ports[1][tuple_addr.l4_id] = true;

		if (!success)
			return success;
	}

	/* The pool ran out of ports. */
	success &= assert_equals_int(-ESRCH, pool4_get_any_addr(proto, 10, &tuple_addr),
			"Exhausted pool");

	return success;
}

static bool test_get_any_addr_function_udp(void)
{
	return test_get_any_addr_aux(L4PROTO_UDP, 0, 1023, 2, 65535 - 512);
}

static bool test_get_any_addr_function_tcp(void)
{
	return test_get_any_addr_aux(L4PROTO_TCP, 0, 1023, 1, 65535 - 1024);
}

static bool test_get_any_addr_function_icmp(void)
{
	return test_get_any_addr_aux(L4PROTO_ICMP, 0, 65535, 1, -1);
}

/**
 * Only UDP and its lower even range of ports is tested here.
 */
static bool test_return_function(void)
{
	struct ipv4_tuple_address tuple_addr;
	__u16 l4_id;
	bool success = true;
	int addr_ctr, port_ctr;

	/* Try to return the entire pool, even though we haven't borrowed anything. */
	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		tuple_addr.address = expected_ips[addr_ctr];
		for (port_ctr = 0; port_ctr < 1024; port_ctr += 2) {
			tuple_addr.l4_id = port_ctr;
			success &= assert_equals_int(-EINVAL, pool4_return(L4PROTO_UDP, &tuple_addr),
					"Returning first");
		}
	}

	/* Borrow the entire pool. */
	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		tuple_addr.address = expected_ips[addr_ctr];
		for (port_ctr = 0; port_ctr < 1024; port_ctr += 2) {
			tuple_addr.l4_id = port_ctr;
			success &= assert_equals_int(0, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
					"Borrow everything-result");
			success &= assert_false(ports[addr_ctr][l4_id], "Borrow everything-port");
			ports[addr_ctr][l4_id] = true;
		}
		success &= assert_equals_int(-ESRCH, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
				"Pool should be exhausted 1");
	}

	if (!success)
		return success;

	/* Return something from the first address. */
	tuple_addr.address = expected_ips[0];
	tuple_addr.l4_id = 1000;
	success &= assert_equals_int(0, pool4_return(L4PROTO_UDP, &tuple_addr), "Return 0-1000 1");

	if (!success)
		return success;

	/* Re-borrow it, assert it's the same one. */
	success &= assert_equals_int(0, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Borrow 0-1000");
	success &= assert_equals_u16(1000, l4_id, "Confirm 0-1000");
	success &= assert_equals_int(-ESRCH, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Reborrow 0-1000");

	if (!success)
		return success;

	/* Do the same to the second address. */
	tuple_addr.address = expected_ips[1];
	tuple_addr.l4_id = 1000;
	success &= assert_equals_int(0, pool4_return(L4PROTO_UDP, &tuple_addr), "Return 1-1000");

	if (!success)
		return success;

	success &= assert_equals_int(0, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Borrow 1-1000");
	success &= assert_equals_u16(1000, l4_id, "Confirm 1-1000");
	success &= assert_equals_int(-ESRCH, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Reborrow 1-1000");

	if (!success)
		return success;

	/* Return some more stuff at once. */
	tuple_addr.address = expected_ips[0];
	tuple_addr.l4_id = 46;
	success &= assert_equals_int(0, pool4_return(L4PROTO_UDP, &tuple_addr), "Return 0-46");

	tuple_addr.l4_id = 1000;
	success &= assert_equals_int(0, pool4_return(L4PROTO_UDP, &tuple_addr), "Return 0-1000 2");

	tuple_addr.address = expected_ips[1];
	tuple_addr.l4_id = 0;
	success &= assert_equals_int(0, pool4_return(L4PROTO_UDP, &tuple_addr), "Return 1-0");

	if (!success)
		return success;

	/* Reborrow it. */
	tuple_addr.address = expected_ips[0];
	tuple_addr.l4_id = 24;
	success &= assert_equals_int(0, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Borrow 0-24");
	success &= assert_true(l4_id == 46 || l4_id == 1000, "Confirm 0-24");

	tuple_addr.l4_id = 100;
	success &= assert_equals_int(0, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Borrow 1-100");
	success &= assert_true(l4_id == 46 || l4_id == 1000, "Confirm 1-100");

	tuple_addr.address = expected_ips[1];
	tuple_addr.l4_id = 56;
	success &= assert_equals_int(0, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Reborrow 2-56");
	success &= assert_equals_u16(0, l4_id, "Confirm 2-56");

	success &= assert_equals_int(-ESRCH, pool4_get_match(L4PROTO_UDP, &tuple_addr, &l4_id),
			"Pool should be exhausted 2");

	if (!success)
		return success;

	/* Now return everything. */
	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		tuple_addr.address = expected_ips[addr_ctr];
		for (port_ctr = 0; port_ctr < 1024; port_ctr += 2) {
			tuple_addr.l4_id = port_ctr;
			success &= assert_equals_int(0, pool4_return(L4PROTO_UDP, &tuple_addr),
					"Returning everything");
		}
	}
	success &= assert_equals_int(-EINVAL, pool4_return(L4PROTO_UDP, &tuple_addr), "Return fail");

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
	START_TESTS("IPv4 Pool");

	INIT_CALL_END(init(), test_get_match_function_udp(), destroy(), "Get match-UDP");
	INIT_CALL_END(init(), test_get_match_function_tcp(), destroy(), "Get match-TCP");
	INIT_CALL_END(init(), test_get_match_function_icmp(), destroy(), "Get match-ICMP");
	INIT_CALL_END(init(), test_get_any_port_function_udp(), destroy(), "Get any port-UDP");
	INIT_CALL_END(init(), test_get_any_port_function_tcp(), destroy(), "Get any port-TCP");
	INIT_CALL_END(init(), test_get_any_port_function_icmp(), destroy(), "Get any port-ICMP");
	INIT_CALL_END(init(), test_get_any_addr_function_udp(), destroy(), "Get any addr-UDP");
	INIT_CALL_END(init(), test_get_any_addr_function_tcp(), destroy(), "Get any addr-TCP");
	INIT_CALL_END(init(), test_get_any_addr_function_icmp(), destroy(), "Get any addr-ICMP");
	INIT_CALL_END(init(), test_return_function(), destroy(), "Return function");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
