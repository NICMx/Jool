#include <linux/module.h>
#include <linux/printk.h>
#include "nat64/unit/unit_test.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Address module test.");

static bool test_count(__u8 prefix_len, __u64 expected)
{
	struct ipv4_prefix prefix;

	get_random_bytes(&prefix.address, sizeof(prefix.address));
	prefix.len = prefix_len;

	return assert_equals_u64(expected, prefix4_get_addr_count(&prefix),
			"count");
}

static bool addr_count_test(void)
{
	bool success = true;

	success &= test_count(32, 1);
	success &= test_count(31, 2);
	success &= test_count(24, 0x100);
	success &= test_count(16, 0x10000);
	success &= test_count(8, 0x1000000);
	success &= test_count(3, 0x20000000);
	success &= test_count(2, 0x40000000);
	success &= test_count(1, 0x80000000);
	success &= test_count(0, 0x100000000);

	return success;
}

static bool test_contains(__u32 prefix_addr, __u8 prefix_len, __u32 addr,
		bool expected)
{
	struct ipv4_prefix prefix;
	struct in_addr inaddr;

	prefix.address.s_addr = cpu_to_be32(prefix_addr);
	prefix.len = prefix_len;
	inaddr.s_addr = cpu_to_be32(addr);

	return assert_equals_int(expected, prefix4_contains(&prefix, &inaddr),
			"contains");
}

static bool contains_test(void)
{
	bool success = true;

	success &= test_contains(0x12345678, 32, 0x12345677, false);
	success &= test_contains(0x12345678, 32, 0x12345678, true);
	success &= test_contains(0x12345678, 32, 0x12345679, false);

	success &= test_contains(0x01020300, 24, 0x010202FF, false);
	success &= test_contains(0x01020300, 24, 0x01020300, true);
	success &= test_contains(0x01020300, 24, 0x010203FF, true);
	success &= test_contains(0x01020300, 24, 0x01020400, false);

	success &= test_contains(0x01020304, 30, 0x01020303, false);
	success &= test_contains(0x01020304, 30, 0x01020304, true);
	success &= test_contains(0x01020304, 30, 0x01020305, true);
	success &= test_contains(0x01020304, 30, 0x01020306, true);
	success &= test_contains(0x01020304, 30, 0x01020307, true);
	success &= test_contains(0x01020304, 30, 0x01020308, false);

	success &= test_contains(0x00000000, 0, 0x00000000, true);
	success &= test_contains(0x00000000, 0, 0x12345678, true);
	success &= test_contains(0x00000000, 0, 0xFFFFFFFF, true);

	return success;
}

int init_module(void)
{
	START_TESTS("Addr");

	CALL_TEST(addr_count_test(), "Addr count");
	CALL_TEST(contains_test(), "Prefix contains");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
