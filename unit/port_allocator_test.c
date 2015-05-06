#include <linux/module.h>
#include "nat64/unit/unit_test.h"
#include "bib/port_allocator.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Port allocator module test.");

static bool test_md5(void)
{
	unsigned char input[6];
	union md5_result result;
	bool success = true;

	input[0] = 'p';
	input[1] = 'o';
	input[2] = 't';
	input[3] = 'a';
	input[4] = 't';
	input[5] = 'o';

	if (!assert_equals_int(0, md5(input, 6, &result), "result"))
		return false;

	/* Expected values gotten from DuckDuckGo. Look up "md5 potato". */
	success &= assert_equals_u32be32(0x8ee20279, result.as32[0], "word 0");
	success &= assert_equals_u32be32(0x83915ec7, result.as32[1], "word 1");
	success &= assert_equals_u32be32(0x8acc4502, result.as32[2], "word 2");
	success &= assert_equals_u32be32(0x7d874316, result.as32[3], "word 3");
	return success;
}

int init_module(void)
{
	START_TESTS("Port Allocator");

	CALL_TEST(test_md5(), "MD5 Test");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
