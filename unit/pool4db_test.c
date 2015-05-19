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
	success &= assert_equals_int(0, init_power(0x80000000U), "rmax");
	success &= assert_equals_uint(0x80000000U, power, "pmax");
	success &= assert_equals_int(-EINVAL, init_power(0x80000001U), "2big1");
	success &= assert_equals_int(-EINVAL, init_power(0xFFFFFFFFU), "2big2");

	return success;
}

struct foreach_args {
	struct ipv4_transport_addr *expected;
	unsigned int expected_len;
	unsigned int i;
};

int validate_entry(struct ipv4_transport_addr *addr, void *void_args)
{
	struct foreach_args *args = void_args;
	bool success = true;

	log_debug("foreaching %pI4:%u", &addr->l3, addr->l4);

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

bool test_foreach_taddr4(void)
{
	struct ipv4_transport_addr expected[12];
	struct ipv4_prefix prefix;
	struct port_range ports;
	struct foreach_args args;
	int error;

	args.expected = expected;
	args.expected_len = ARRAY_SIZE(expected);

	prefix.address.s_addr = cpu_to_be32(0xc0000200);
	prefix.len = 31;
	ports.min = 6;
	ports.max = 7;
	if (!assert_equals_int(0, pool4db_add(1, &prefix, &ports), "add 1"))
		return false;
	prefix.address.s_addr = cpu_to_be32(0xc0000210);
	prefix.len = 32;
	ports.min = 15;
	ports.max = 19;
	if (!assert_equals_int(0, pool4db_add(1, &prefix, &ports), "add 2"))
		return false;
	prefix.address.s_addr = cpu_to_be32(0xc0000220);
	prefix.len = 30;
	ports.min = 1;
	ports.max = 1;
	if (!assert_equals_int(0, pool4db_add(1, &prefix, &ports), "add 3"))
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
	error = pool4db_foreach_taddr4(1, validate_entry, &args, 0);
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
	error = pool4db_foreach_taddr4(1, validate_entry, &args, 9);
	return assert_equals_int(0, error, "call 2");
}

bool init(void)
{
	int error;

	error = pool4db_init(4, NULL, 0);
	if (error) {
		log_err("Errcode on pool4 init: %d", error);
		return false;
	}

	return true;
}

void destroy(void)
{
	pool4db_destroy();
}

int init_module(void)
{
	START_TESTS("IPv4 Pool DB");

	INIT_CALL_END(init(), test_init_power(), destroy(), "Power init");
	INIT_CALL_END(init(), test_foreach_taddr4(), destroy(), "Foreachs");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
