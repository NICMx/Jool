#include <linux/module.h>
#include "mod/common/db/pool4/rfc6056.c"
#include "framework/types.h"
#include "framework/unit_test.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Port allocator module test.");

static bool test_f(void)
{
	struct xlation state;
	struct tuple *tuple6;
	__u32 shash;
	__u32 phash;
	bool success = true;

	xlation_init(&state, NULL);
	tuple6 = &state.in.tuple;

	tuple6->src.addr6.l3.s6_addr[0] = 'a';
	tuple6->src.addr6.l3.s6_addr[1] = 'b';
	tuple6->src.addr6.l3.s6_addr[2] = 'c';
	tuple6->src.addr6.l3.s6_addr[3] = 'd';
	tuple6->src.addr6.l3.s6_addr[4] = 'e';
	tuple6->src.addr6.l3.s6_addr[5] = 'f';
	tuple6->src.addr6.l3.s6_addr[6] = 'g';
	tuple6->src.addr6.l3.s6_addr[7] = 'h';
	tuple6->src.addr6.l3.s6_addr[8] = 'i';
	tuple6->src.addr6.l3.s6_addr[9] = 'j';
	tuple6->src.addr6.l3.s6_addr[10] = 'k';
	tuple6->src.addr6.l3.s6_addr[11] = 'l';
	tuple6->src.addr6.l3.s6_addr[12] = 'm';
	tuple6->src.addr6.l3.s6_addr[13] = 'n';
	tuple6->src.addr6.l3.s6_addr[14] = 'o';
	tuple6->src.addr6.l3.s6_addr[15] = 'p';
	tuple6->src.addr6.l4 = (__force __u16)cpu_to_be16(('q' << 8) | 'r');
	tuple6->dst.addr6.l3.s6_addr[0] = 's';
	tuple6->dst.addr6.l3.s6_addr[1] = 't';
	tuple6->dst.addr6.l3.s6_addr[2] = 'u';
	tuple6->dst.addr6.l3.s6_addr[3] = 'v';
	tuple6->dst.addr6.l3.s6_addr[4] = 'w';
	tuple6->dst.addr6.l3.s6_addr[5] = 'x';
	tuple6->dst.addr6.l3.s6_addr[6] = 'y';
	tuple6->dst.addr6.l3.s6_addr[7] = 'z';
	tuple6->dst.addr6.l3.s6_addr[8] = 'A';
	tuple6->dst.addr6.l3.s6_addr[9] = 'B';
	tuple6->dst.addr6.l3.s6_addr[10] = 'C';
	tuple6->dst.addr6.l3.s6_addr[11] = 'D';
	tuple6->dst.addr6.l3.s6_addr[12] = 'E';
	tuple6->dst.addr6.l3.s6_addr[13] = 'F';
	tuple6->dst.addr6.l3.s6_addr[14] = 'G';
	tuple6->dst.addr6.l3.s6_addr[15] = 'H';
	tuple6->dst.addr6.l4 = (__force __u16)cpu_to_be16(('I' << 8) | 'J');

	secret_key[0] = 'K';
	secret_key[1] = 'L';
	secret_key_len = 2;

	success &= ASSERT_INT(0, rfc6056_f(&state, &shash, &phash), "errcode");
	/* MD5("abcdefghijklmnopKL") = 0x71ba00cc749f861f488b4c86c5858dc0 */
	success &= ASSERT_BE32(0xc5858dc0u, (__force __be32)shash, "addr");
	/* MD5("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL") = 0x2dffea1088e039d98e57ab255bcd4b75 */
	success &= ASSERT_BE32(0x5bcd4b75u, (__force __be32)phash, "port");

	return success;
}

int init_module(void)
{
	struct test_group test = {
		.name = "Port Allocator",
		.setup_fn = rfc6056_setup,
		.teardown_fn = rfc6056_teardown,
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, test_f, "MD5 Test");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
