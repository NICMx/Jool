#include <linux/module.h>
#include <linux/slab.h>

#include "unit_test.h"
#include "nf_nat64_ipv4_pool.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("IPv4 pool module test");


// TODO (test) va a faltar testear situaciones de error.

#define PORT_RANGE1_MAX 1023
#define PORT_RANGE2_MAX 65535

const char* expected_ips_as_str[] = { "192.168.2.1", "192.168.2.2" };
struct in_addr expected_ips[ARRAY_SIZE(expected_ips_as_str)];

/**
 * These are used by a couple of tests.
 * They're too big for the stack frame limit, and I don't feel like meddling with kmallocs,
 * so here they are.
 *
 * They store the results of the functions being tested (since we need a lot of calls).
 * Note that the array index is not related to the way the functions work.
 * We're assigning the n port to the n index for convenience only.
 */
struct ipv4_tuple_address results1[1024], results2[1024];


static bool assert_tuple_addr(struct in_addr *expected_address, __u16 expected_port,
		struct ipv4_tuple_address *actual, char *test_name)
{
	bool success = true;
	success &= assert_equals_ipv4(expected_address, &actual->address, test_name);
	success &= assert_equals_u16(expected_port, actual->l4_id, test_name);
	return success;
}

static bool test_range(__u32 port_range_min, __u32 port_range_max, char *test_name)
{
	__u32 addr_ctr, port_ctr;
	struct ipv4_tuple_address result;
	bool success = true;

	for (addr_ctr = 0; addr_ctr < ARRAY_SIZE(expected_ips); addr_ctr++) {
		for (port_ctr = port_range_min; port_ctr <= port_range_max; port_ctr += 2) {
			success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(port_range_min), &result),
					test_name);
			success &= assert_tuple_addr(&expected_ips[addr_ctr], port_ctr, &result, test_name);

//			if (port_ctr % 20 == 0 && !success)
//				return false;
		}
	}

	success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(port_range_min), &result),
			test_name);
	success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(port_range_min), &result),
			test_name);

	return success;
}

/**
 * The get_any function cannot be fully tested on its own, so the basics are here and some more
 * hacking is done in test_return_function().
 *
 * Tests to some extent that the different ranges do not interfere with each other during gets.
 */
static bool test_get_any_function(void)
{
	if (!test_range(0, PORT_RANGE1_MAX, "Even low ports"))
		return false;
	if (!test_range(1, PORT_RANGE1_MAX, "Odd low ports"))
		return false;
	if (!test_range(1024, PORT_RANGE2_MAX, "Even high ports"))
		return false;
	if (!test_range(1025, PORT_RANGE2_MAX, "Odd high ports"))
		return false;

	return true;
}

/**
 * The return function cannot be tested on its own, so here's also the rest of the get_any test.
 *
 * Purpose is to test get returns address/ports in the expected order, given different combinations
 * of return calls.
 * We only use the lower even range of ports, since the rest was tested during
 * test_get_any_function().
 */
static bool test_return_function(void)
{
	bool success = true;
	int i;

	memset(&results1, 0, sizeof(results1));
	memset(&results2, 0, sizeof(results2));

	// Borrow the entire first address.
	for (i = 0; i < 1024; i += 2) {
		success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(i), &results1[i]),
				"Borrow Addr1-res");
		success &= assert_tuple_addr(&expected_ips[0], i, &results1[i], "Borrow Addr1-out");
	}

	// Borrow the first port of the second address.
	success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(0), &results2[0]),
			"Borrow Addr2-res-port0");
	success &= assert_tuple_addr(&expected_ips[1], 0, &results2[0], "Borrow Addr2-out-port0");

	// Return the last one.
	success &= assert_true(pool4_return(IPPROTO_UDP, &results2[0]), "Return Addr2-port0");
	if (!success)
		return success;

	// Reborrow it.
	success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(0), &results2[0]),
			"Reborrow Addr2-res-port0");
	success &= assert_tuple_addr(&expected_ips[1], 0, &results2[0], "Reborrow Addr2-out-port0");
	if (!success)
		return success;

	// Return some more stuff.
	success &= assert_true(pool4_return(IPPROTO_UDP, &results1[46]), "Return Addr1-port46");
	success &= assert_true(pool4_return(IPPROTO_UDP, &results1[1000]), "Return Addr1-port1000");
	success &= assert_true(pool4_return(IPPROTO_UDP, &results2[0]), "ReReturn Addr2-port0");
	if (!success)
		return success;

	// Reborrow it.
	success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(24), &results1[46]),
			"Reborrow Addr1-res-port46");
	success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(1010), &results1[1000]),
			"Reborrow Addr1-res-port1000");
	success &= assert_true(pool4_get_any(IPPROTO_UDP, cpu_to_be16(56), &results2[0]),
			"ReReborrow Addr2-res-port0");
	success &= assert_tuple_addr(&expected_ips[0], 46, &results1[46],
			"Reborrow Addr1-out-port46");
	success &= assert_tuple_addr(&expected_ips[0], 1000, &results1[1000],
			"Reborrow Addr1-out-port1000");
	success &= assert_tuple_addr(&expected_ips[1], 0, &results2[0],
			"ReReborrow Addr2-out-port0");

	return success;
}

static bool test_get_similar_function(void)
{
	struct ipv4_tuple_address query;
	struct ipv4_tuple_address null_result;
	bool success = true;
	int i;

	memset(&results1, 0, sizeof(results1));
	memset(&results2, 0, sizeof(results2));

	// Borrow the entire first address.
	query.address = expected_ips[0];
	query.l4_id = 24;
	for (i = 0; i < 1024; i += 2) {
		success &= assert_true(pool4_get_similar(IPPROTO_UDP, &query, &results1[i]),
				"Borrow Addr1-res");
		success &= assert_tuple_addr(&expected_ips[0], i, &results1[i], "Borrow Addr1-out");
	}

	success &= assert_false(pool4_get_similar(IPPROTO_UDP, &query, &null_result),
			"Borrow Addr1-Exhausted (1)");
	success &= assert_false(pool4_get_similar(IPPROTO_UDP, &query, &null_result),
			"Borrow Addr1-Exhausted (2)");

	if (!success)
		return success;

	// Borrow some from the second address.
	query.address = expected_ips[1];
	query.l4_id = 888;
	for (i = 0; i < 512; i += 2) {
		success &= assert_true(pool4_get_similar(IPPROTO_UDP, &query, &results2[i]),
				"Borrow Addr2-res");
		success &= assert_tuple_addr(&expected_ips[1], i, &results2[i], "Borrow Addr2-out");
	}

	if (!success)
		return success;

	// Now return stuff in some disorganized manner.
	success &= assert_true(pool4_return(IPPROTO_UDP, &results2[64]), "Return Addr2-port64");
	success &= assert_true(pool4_return(IPPROTO_UDP, &results1[128]), "Return Addr1-port128");
	success &= assert_true(pool4_return(IPPROTO_UDP, &results1[32]), "Return Addr2-port32");
	success &= assert_true(pool4_return(IPPROTO_UDP, &results2[256]), "Return Addr1-port256");

	// Reborrow it.
	query.l4_id = 334;

	query.address = expected_ips[0];
	success &= assert_true(pool4_get_similar(IPPROTO_UDP, &query, &results1[128]),
			"Get-Return mix (res), 128");
	query.address = expected_ips[1];
	success &= assert_true(pool4_get_similar(IPPROTO_UDP, &query, &results2[64]),
			"Get-Return mix, (res) 64");
	query.address = expected_ips[0];
	success &= assert_true(pool4_get_similar(IPPROTO_UDP, &query, &results1[32]),
			"Get-Return mix, (res) 32");
	query.address = expected_ips[1];
	success &= assert_true(pool4_get_similar(IPPROTO_UDP, &query, &results2[256]),
			"Get-Return mix, (res) 256");
	query.address = expected_ips[0];
	success &= assert_false(pool4_get_similar(IPPROTO_UDP, &query, &null_result),
			"Borrow Addr1-Exhausted (3)");

	success &= assert_tuple_addr(&expected_ips[0], 128, &results1[128],
			"Get-Return mix (out), 128");
	success &= assert_tuple_addr(&expected_ips[1], 64, &results2[64],
			"Get-Return mix (out), 64");
	success &= assert_tuple_addr(&expected_ips[0], 32, &results1[32],
			"Get-Return mix (out), 32");
	success &= assert_tuple_addr(&expected_ips[1], 256, &results2[256],
			"Get-Return mix (out), 256");

	return success;
}

static bool init(void)
{
	int i;

	if (!pool4_init()) {
		log_warning("Could not init the pool. Failing...");
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(expected_ips); i++) {
		if (!str_to_addr4(expected_ips_as_str[i], &expected_ips[i])) {
			log_warning("Cannot parse test address '%s'. Failing.", expected_ips_as_str[i]);
			return false;
		}

		if (!pool4_register(&expected_ips[i])) {
			log_warning("Could not register address %pI4. Failing...", &expected_ips[i]);
			return false;
		}
	}

	return true;
}

static void destroy(void)
{
	pool4_destroy();
}

int init_module(void)
{
	START_TESTS("Pool");

	INIT_CALL_END(init(), test_get_any_function(), destroy(), "Get simple");
	INIT_CALL_END(init(), test_return_function(), destroy(), "Get and Return");
	INIT_CALL_END(init(), test_get_similar_function(), destroy(), "Allocate functions");

	END_TESTS;
}
void cleanup_module(void)
{
	// No code.
}
