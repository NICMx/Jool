#include <linux/kernel.h>
#include <linux/module.h>

#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/stateful/pool4/customer.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/pool4/rfc6056.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("IPv4 pool customer module test");

#define EXPECTED_ARRAY { /* port:  1  2  3  4 */ \
		/* 192.0.2.0 */  { 0, 0, 0, 0 }, \
		/* 192.0.2.1 */  { 0, 0, 0, 0 }, \
		/* 192.0.2.2 */  { 0, 0, 0, 0 }, \
		/* 192.0.2.3 */  { 0, 0, 0, 0 }, \
		/* 192.0.2.4 */  { 0, 0, 0, 0 }, \
		/* 192.0.2.5 */  { 0, 0, 0, 0 }, \
		/* 192.0.2.6 */  { 0, 0, 0, 0 }, \
		/* 192.0.2.7 */  { 0, 0, 0, 0 }, \
	}

bool expected[8][4] = EXPECTED_ARRAY;
bool actual[8][4] = EXPECTED_ARRAY;

static struct pool4 *init_pool(__u8 b, __u8 c, __u8 e, __u8 f)
{
	struct pool4 *pool;
	struct customer_entry_usr entry;

	if (pool4db_init(&pool))
		return false;

	if (str_to_addr6("2001:db8::", &entry.prefix6.address))
		goto fail;
	entry.prefix6.len = b;
	entry.groups6_size_len = c;
	if (str_to_addr4("192.0.2.0", &entry.prefix4.address))
		goto fail;
	entry.prefix4.len = e;
	entry.ports_division_len = f;
	entry.ports.min = 1;
	entry.ports.max = 4;
	if (customerdb_add(pool, &entry))
		goto fail;

	return pool;

fail:
	pool4db_put(pool);
	return NULL;
}

static void print_array(char *prefix, bool array[][4])
{
	unsigned int a, p;

	pr_err("%s: ", prefix);
	for (a = 0; a < ARRAY_SIZE(expected); a++)
		for (p = 0; p < ARRAY_SIZE(expected[a]); p++)
			if (array[a][p])
				pr_cont("192.0.2.%u#%u, ", a, p + 1);
	pr_cont("\n");
}

static bool report_failure(char *addr)
{
	pr_err("Failure on address %s!\n", addr);
	print_array("Expected", expected);
	print_array("Actual  ", actual);
	return false;
}

static bool compare_expected_vs_actual(char *addr)
{
	unsigned int a, p;

	for (a = 0; a < ARRAY_SIZE(expected); a++)
		for (p = 0; p < ARRAY_SIZE(expected[a]); p++)
			if (expected[a][p] != actual[a][p])
				return report_failure(addr);

	return true;
}

static bool test_address(struct pool4 *pool, char *addr_str)
{
	struct tuple tuple6;
	struct mask_domain *masks;
	struct ipv4_transport_addr addr;
	bool consecutive; /* TODO I found a bug with this value. Report. */

	memset(&actual, 0, sizeof(actual));
	memset(&tuple6, 0, sizeof(tuple6));
	if (str_to_addr6(addr_str, &tuple6.src.addr6.l3))
		return false;

	masks = mask_domain_find(pool, &tuple6, 0b1011, NULL);
	if (!ASSERT_BOOL(true, masks != NULL, "masks != NULL"))
		return false;

	while (!mask_domain_next(masks, &addr, &consecutive))
		actual[be32_to_cpu(addr.l3.s_addr) & 0xFF][addr.l4 - 1] = true;

	return compare_expected_vs_actual(addr_str);
}

static bool test_simple(struct pool4 *pool, char *addr6,
		int addr4_1, int addr4_2)
{
	memset(expected, 0, sizeof(expected));
	memset(expected[addr4_1], 1, sizeof(expected[addr4_1]));
	memset(expected[addr4_2], 1, sizeof(expected[addr4_2]));
	return test_address(pool, addr6);
}

static bool test_sequential(void)
{
	struct pool4 *pool;
	bool success = true;

	pool = init_pool(125, 127, 29, 29);
	if (!pool)
		return false;

	success &= test_simple(pool, "2001:db8::", 0, 1);
	success &= test_simple(pool, "2001:db8::1", 0, 1);
	success &= test_simple(pool, "2001:db8::2", 2, 3);
	success &= test_simple(pool, "2001:db8::3", 2, 3);
	success &= test_simple(pool, "2001:db8::4", 4, 5);
	success &= test_simple(pool, "2001:db8::5", 4, 5);
	success &= test_simple(pool, "2001:db8::6", 6, 7);
	success &= test_simple(pool, "2001:db8::7", 6, 7);

	pool4db_put(pool);
	return success;
}

static bool test_round_robin(void)
{
	struct pool4 *pool;
	bool success = true;

	pool = init_pool(125, 127, 29, 30);
	if (!pool)
		return false;

	success &= test_simple(pool, "2001:db8::", 0, 4);
	success &= test_simple(pool, "2001:db8::1", 0, 4);
	success &= test_simple(pool, "2001:db8::2", 1, 5);
	success &= test_simple(pool, "2001:db8::3", 1, 5);
	success &= test_simple(pool, "2001:db8::4", 2, 6);
	success &= test_simple(pool, "2001:db8::5", 2, 6);
	success &= test_simple(pool, "2001:db8::6", 3, 7);
	success &= test_simple(pool, "2001:db8::7", 3, 7);

	pool4db_put(pool);
	return success;
}

int init_module(void)
{
	START_TESTS("Customer");

	if (rfc6056_init())
		return -EINVAL;

	CALL_TEST(test_sequential(), "Sequential");
	CALL_TEST(test_round_robin(), "Round Robin");
	/* CALL_TEST(test(), "Interlaced Horizontally"); */

	rfc6056_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
