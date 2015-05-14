#include <linux/kernel.h>
#include <linux/module.h>

#include "nat64/unit/unit_test.h"
#include "pool4/db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("IPv4 pool DB module test");

static bool test_init_power(void)
{
	bool success = true;

	success &= assert_equals_int(0, init_power(0), "r0");
	success &= assert_equals_uint(1U, power, "p0");
	success &= assert_equals_int(0, init_power(1), "r1");
	success &= assert_equals_uint(1U, power, "p1");
	success &= assert_equals_int(0, init_power(2), "r2");
	success &= assert_equals_uint(2U, power, "p2");
	success &= assert_equals_int(0, init_power(3), "r3");
	success &= assert_equals_uint(4U, power, "p3");
	success &= assert_equals_int(0, init_power(4), "r4");
	success &= assert_equals_uint(4U, power, "p4");
	success &= assert_equals_int(0, init_power(5), "r5");
	success &= assert_equals_uint(8U, power, "p5");
	success &= assert_equals_int(0, init_power(1234), "r1234");
	success &= assert_equals_uint(2048U, power, "p1234");
	success &= assert_equals_int(0, init_power(0x7FFFFFFFU), "rmax");
	success &= assert_equals_uint(0x80000000U, power, "pmax");
	success &= assert_equals_int(-EINVAL, init_power(0x80000000U), "roverflow1");
	success &= assert_equals_int(-EINVAL, init_power(0xFFFFFFFFU), "roverflow2");

	return success;
}

int init_module(void)
{
	START_TESTS("IPv4 Pool DB");

	CALL_TEST(test_init_power(), "Power initialization");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
