#include <linux/module.h>
#include "nat64/unit/unit_test.h"
#include "bib/port_allocator.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Port allocator module test.");

static bool test_md5(void)
{
	struct in6_addr arg1;
	struct in6_addr arg2;
	union {
		__u16 as16;
		__u8 as8[2];
	} arg3;
	unsigned int result;

	arg1.s6_addr[0] = 'a';
	arg1.s6_addr[1] = 'b';
	arg1.s6_addr[2] = 'c';
	arg1.s6_addr[3] = 'd';
	arg1.s6_addr[4] = 'e';
	arg1.s6_addr[5] = 'f';
	arg1.s6_addr[6] = 'g';
	arg1.s6_addr[7] = 'h';
	arg1.s6_addr[8] = 'i';
	arg1.s6_addr[9] = 'j';
	arg1.s6_addr[10] = 'k';
	arg1.s6_addr[11] = 'l';
	arg1.s6_addr[12] = 'm';
	arg1.s6_addr[13] = 'n';
	arg1.s6_addr[14] = 'o';
	arg1.s6_addr[15] = 'p';

	arg2.s6_addr[0] = 'q';
	arg2.s6_addr[1] = 'r';
	arg2.s6_addr[2] = 's';
	arg2.s6_addr[3] = 't';
	arg2.s6_addr[4] = 'u';
	arg2.s6_addr[5] = 'v';
	arg2.s6_addr[6] = 'w';
	arg2.s6_addr[7] = 'x';
	arg2.s6_addr[8] = 'y';
	arg2.s6_addr[9] = 'z';
	arg2.s6_addr[10] = 'A';
	arg2.s6_addr[11] = 'B';
	arg2.s6_addr[12] = 'C';
	arg2.s6_addr[13] = 'D';
	arg2.s6_addr[14] = 'E';
	arg2.s6_addr[15] = 'F';

	arg3.as8[0] = 'G';
	arg3.as8[1] = 'H';

	secret_key[0] = 'I';
	secret_key[1] = 'J';
	secret_key_len = 2;

	/* Expected value gotten from DuckDuckGo. Look up "md5 abcdefg...". */
	return ASSERT_INT(0, f(&arg1, &arg2, arg3.as16, &result), "errcode")
			&& ASSERT_BE32(0xb6a824a9u, result, "hash");
}

bool init(void)
{
	return !palloc_init();
}

int init_module(void)
{
	START_TESTS("Port Allocator");

	INIT_CALL_END(init(), test_md5(), palloc_destroy(), "MD5 Test");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
