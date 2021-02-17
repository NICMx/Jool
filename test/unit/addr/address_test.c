#include <linux/module.h>
#include <linux/printk.h>

#include "framework/address.h"
#include "framework/unit_test.h"


MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Address module test.");

static bool test_count(__u8 prefix_len, __u64 expected)
{
	struct ipv4_prefix prefix;

	get_random_bytes(&prefix.addr, sizeof(prefix.addr));
	prefix.len = prefix_len;

	return ASSERT_U64(expected, prefix4_get_addr_count(&prefix),
			"Address count of /%u", prefix_len);
}

static bool addr_count_test(void)
{
	bool success = true;

	success &= test_count(32, 1U);
	success &= test_count(31, 2U);
	success &= test_count(24, 0x100U);
	success &= test_count(16, 0x10000U);
	success &= test_count(8, 0x1000000U);
	success &= test_count(3, 0x20000000U);
	success &= test_count(2, 0x40000000U);
	success &= test_count(1, 0x80000000U);
	success &= test_count(0, 0x100000000UL);

	return success;
}

static bool test_contains(__u32 prefix_addr, __u8 prefix_len, __u32 addr,
		bool expected)
{
	struct ipv4_prefix prefix;
	struct in_addr inaddr;

	prefix.addr.s_addr = cpu_to_be32(prefix_addr);
	prefix.len = prefix_len;
	inaddr.s_addr = cpu_to_be32(addr);

	return ASSERT_BOOL(expected, prefix4_contains(&prefix, &inaddr),
			"%pI4/%u contains %pI4",
			&prefix.addr, prefix.len, &inaddr);
}

static bool contains_test(void)
{
	bool success = true;

	success &= test_contains(0x12345678U, 32, 0x12345677U, false);
	success &= test_contains(0x12345678U, 32, 0x12345678U, true);
	success &= test_contains(0x12345678U, 32, 0x12345679U, false);

	success &= test_contains(0x01020300U, 24, 0x010202FFU, false);
	success &= test_contains(0x01020300U, 24, 0x01020300U, true);
	success &= test_contains(0x01020300U, 24, 0x010203FFU, true);
	success &= test_contains(0x01020300U, 24, 0x01020400U, false);

	success &= test_contains(0x01020304U, 30, 0x01020303U, false);
	success &= test_contains(0x01020304U, 30, 0x01020304U, true);
	success &= test_contains(0x01020304U, 30, 0x01020305U, true);
	success &= test_contains(0x01020304U, 30, 0x01020306U, true);
	success &= test_contains(0x01020304U, 30, 0x01020307U, true);
	success &= test_contains(0x01020304U, 30, 0x01020308U, false);

	success &= test_contains(0x00000000U, 0, 0x00000000U, true);
	success &= test_contains(0x00000000U, 0, 0x12345678U, true);
	success &= test_contains(0x00000000U, 0, 0xFFFFFFFFU, true);

	return success;
}

static bool test_addr6_copy_bits(char const *test_str, unsigned int offset,
		unsigned int len, char const *expected, char const *test_name)
{
	struct in6_addr test;
	struct in6_addr actual;

	if (str_to_addr6(test_str, &test))
		return false;
	memset(&actual, 0, sizeof(actual));

	addr6_copy_bits(&test, &actual, offset, len);
	return ASSERT_ADDR6(expected, &actual, test_name);
}

static bool addr6_copy_bits_test(void)
{
	/*                   0    16   32   48   64   80   96   112 */
	char const *NOISE = "0f78:1e69:2d5a:3c4b:4b3c:5a2d:691e:780f";
	char const *ONES  = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
	bool success = true;

	/* Full address */
	success &= test_addr6_copy_bits(NOISE, 0, 128, NOISE, "Full copy");

	/* Zero length */
	success &= test_addr6_copy_bits(ONES, 0,   0, "::", "No copy 1");
	success &= test_addr6_copy_bits(ONES, 8,   0, "::", "No copy 2");
	success &= test_addr6_copy_bits(ONES, 64,  0, "::", "No copy 3");
	success &= test_addr6_copy_bits(ONES, 65,  0, "::", "No copy 4");
	success &= test_addr6_copy_bits(ONES, 66,  0, "::", "No copy 5");
	success &= test_addr6_copy_bits(ONES, 67,  0, "::", "No copy 6");
	success &= test_addr6_copy_bits(ONES, 68,  0, "::", "No copy 7");
	success &= test_addr6_copy_bits(ONES, 69,  0, "::", "No copy 8");
	success &= test_addr6_copy_bits(ONES, 70,  0, "::", "No copy 9");
	success &= test_addr6_copy_bits(ONES, 71,  0, "::", "No copy 10");
	success &= test_addr6_copy_bits(ONES, 128, 0, "::", "No copy 11");

	/* 1 bit */
	success &= test_addr6_copy_bits(ONES, 0, 1, "8000::", "1 bit (byte head, bit head)");
	success &= test_addr6_copy_bits(ONES, 1, 1, "4000::", "1 bit (byte head, bit mid)");
	success &= test_addr6_copy_bits(ONES, 7, 1, "0100::", "1 bit (byte head, bit tail)");
	success &= test_addr6_copy_bits(ONES, 8, 1, "80::", "1 bit (byte mid, bit head)");
	success &= test_addr6_copy_bits(ONES, 61, 1, "0:0:0:4::", "1 bit (byte mid, bit mid)");
	success &= test_addr6_copy_bits(ONES, 87, 1, "::100:0:0", "1 bit (byte mid, bit tail)");
	success &= test_addr6_copy_bits(ONES, 120, 1, "::80", "1 bit (byte tail, bit head)");
	success &= test_addr6_copy_bits(ONES, 124, 1, "::8", "1 bit (byte tail, bit mid)");
	success &= test_addr6_copy_bits(ONES, 127, 1, "::1", "1 bit (byte tail, bit tail)");

	/* Left aligns, right aligns */
	success &= test_addr6_copy_bits(NOISE, 0, 8, "f00::", "LARA byte head");
	success &= test_addr6_copy_bits(NOISE, 40, 8, "0:0:5a::", "LARA byte mid");
	success &= test_addr6_copy_bits(NOISE, 120, 8, "::f", "LARA byte tail");

	success &= test_addr6_copy_bits(NOISE, 0, 24, "f78:1e00::", "LARA bytes head");
	success &= test_addr6_copy_bits(NOISE, 64, 16, "::4b3c:0:0:0", "LARA bytes mid");
	success &= test_addr6_copy_bits(NOISE, 96, 32, "::691e:780f", "LARA bytes tail");

	/* Left aligns, right does not align, < 1 byte */
	success &= test_addr6_copy_bits(ONES, 0, 7, "fe00::", "LARN < head");
	success &= test_addr6_copy_bits(ONES, 8, 4, "f0::", "LARN < mid");
	success &= test_addr6_copy_bits(ONES, 120, 5, "::f8", "LARN < tail");

	/* Left aligns, right does not align, > 1 byte */
	success &= test_addr6_copy_bits(NOISE, 0, 21, "f78:1800::", "LARN > head");
	success &= test_addr6_copy_bits(NOISE, 8, 43, "78:1e69:2d5a:2000::", "LARN > mid");
	success &= test_addr6_copy_bits(NOISE, 112, 15, "::780e", "LARN > tail");

	/* Left does not align, right aligns, < 1 byte */
	success &= test_addr6_copy_bits(NOISE, 1, 7, "f00::", "LNRA < head");
	success &= test_addr6_copy_bits(NOISE, 77, 3, "::4:0:0:0", "LNRA < mid");
	success &= test_addr6_copy_bits(NOISE, 125, 3, "::7", "LNRA < tail");

	/* Left does not align, right aligns, > 1 byte */
	success &= test_addr6_copy_bits(NOISE, 1, 23, "f78:1e00::", "LNRA > head");
	success &= test_addr6_copy_bits(NOISE, 59, 21, "0:0:0:b:4b3c::", "LNRA > mid");
	success &= test_addr6_copy_bits(NOISE, 119, 9, "::f", "LNRA > tail");

	/* Left does not align, right does not align, < 1 byte */
	success &= test_addr6_copy_bits(ONES, 1, 4, "7800::", "LNRN < head");
	success &= test_addr6_copy_bits(NOISE, 37, 5, "0:0:540::", "LNRN < mid");
	success &= test_addr6_copy_bits(NOISE, 124, 3, "::e", "LNRN < tail");

	/* Left does not align, right does not align, 1 byte (no middlebytes) */
	success &= test_addr6_copy_bits(ONES, 1, 8, "7f80::", "LNRN = head");
	success &= test_addr6_copy_bits(NOISE, 77, 8, "::4:5800:0:0", "LNRN = mid");
	success &= test_addr6_copy_bits(ONES, 119, 8, "::1fe", "LNRN = tail");

	/* Left does not align, right does not align, > 1 byte (with middlebytes) */
	success &= test_addr6_copy_bits(ONES, 1, 17, "7fff:c000::", "LNRN > head");
	success &= test_addr6_copy_bits(NOISE, 51, 33, "0:0:0:1c4b:4b3c:5000::", "LNRN > mid");
	success &= test_addr6_copy_bits(NOISE, 98, 29, "::291e:780e", "LNRN > tail");

	return success;
}

int init_module(void)
{
	struct test_group test = {
		.name = "Addr",
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, addr_count_test, "Addr count");
	test_group_test(&test, contains_test, "Prefix contains");
	test_group_test(&test, addr6_copy_bits_test, "Address copy bits");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
