#include <linux/kernel.h>
#include <linux/module.h>

#include "nat64/unit/unit_test.h"
#include "pool4/pool4.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("IPv4 pool module test");

struct foreach_args {
	struct ipv4_transport_addr *expected;
	unsigned int expected_len;
	unsigned int i;
};

int validate_entry(struct ipv4_transport_addr *addr, void *void_args)
{
	struct foreach_args *args = void_args;
	bool success = true;

	success &= assert_true(args->i < args->expected_len, "iteration limit");
	if (!success)
		return -EINVAL;

	success &= assert_equals_ipv4(&args->expected[args->i].l3, &addr->l3, "addr");
	success &= assert_equals_u16(args->expected[args->i].l4, addr->l4, "port");

	args->i++;
	return success ? 0 : -EINVAL;
}

static void init_addr(struct ipv4_transport_addr *taddr, __u32 addr, __u16 port)
{
	taddr->l3.s_addr = cpu_to_be32(addr);
	taddr->l4 = port;
}

static bool test_foreach_port(void)
{
	struct ipv4_transport_addr expected[12];
	struct pool4_sample sample;
	struct foreach_args args;
	int error;

	args.expected = expected;
	args.expected_len = ARRAY_SIZE(expected);

	sample.prefix.address.s_addr = cpu_to_be32(0xc0000200);
	sample.prefix.len = 31;
	sample.range.min = 6;
	sample.range.max = 7;
	if (!assert_equals_int(0, pool4_add(&sample), "add result"))
		return false;
	sample.prefix.address.s_addr = cpu_to_be32(0xc0000210);
	sample.prefix.len = 32;
	sample.range.min = 15;
	sample.range.max = 19;
	if (!assert_equals_int(0, pool4_add(&sample), "add result"))
		return false;
	sample.prefix.address.s_addr = cpu_to_be32(0xc0000220);
	sample.prefix.len = 30;
	sample.range.min = 1;
	sample.range.max = 1;
	if (!assert_equals_int(0, pool4_add(&sample), "add result"))
		return false;

	init_addr(&expected[0], 0xc0000200, 6);
	init_addr(&expected[1], 0xc0000200, 7);
	init_addr(&expected[2], 0xc0000201, 6);
	init_addr(&expected[3], 0xc0000201, 7);
	init_addr(&expected[4], 0xc0000210, 15);
	init_addr(&expected[5], 0xc0000210, 16);
	init_addr(&expected[6], 0xc0000210, 17);
	init_addr(&expected[7], 0xc0000210, 18);
	init_addr(&expected[8], 0xc0000220, 1);
	init_addr(&expected[9], 0xc0000221, 1);
	init_addr(&expected[10], 0xc0000222, 1);
	init_addr(&expected[11], 0xc0000223, 1);

	args.i = 0;
	error = pool4_foreach_port(1, validate_entry, &args, 0);
	if (!assert_equals_int(0, error, "call 1"))
		return false;

	init_addr(&expected[0], 0xc0000221, 1);
	init_addr(&expected[1], 0xc0000222, 1);
	init_addr(&expected[2], 0xc0000223, 1);
	init_addr(&expected[3], 0xc0000200, 6);
	init_addr(&expected[4], 0xc0000200, 7);
	init_addr(&expected[5], 0xc0000201, 6);
	init_addr(&expected[6], 0xc0000201, 7);
	init_addr(&expected[7], 0xc0000210, 15);
	init_addr(&expected[8], 0xc0000210, 16);
	init_addr(&expected[9], 0xc0000210, 17);
	init_addr(&expected[10], 0xc0000210, 18);
	init_addr(&expected[11], 0xc0000220, 1);

	args.i = 0;
	error = pool4_foreach_port(1, validate_entry, &args, 9);
	return assert_equals_int(0, error, "call 2");
}

int init_module(void)
{
	int error;
	START_TESTS("IPv4 Pool");

	error = pool4_init(NULL, 0);
	if (error)
		return -EINVAL;

	CALL_TEST(test_foreach_port(), "foreach port");

	pool4_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
