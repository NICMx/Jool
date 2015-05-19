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

/**
 * add - Boilerplate code to add an entry to the pool during the tests.
 */
static bool add(__u32 addr, __u8 prefix_len, __u16 min, __u16 max)
{
	struct ipv4_prefix prefix;
	struct port_range ports;

	prefix.address.s_addr = cpu_to_be32(addr);
	prefix.len = prefix_len;
	ports.min = min;
	ports.max = max;

	return assert_equals_int(0, pool4db_add(1, &prefix, &ports), "add");
}

static bool rm(__u32 addr, __u8 prefix_len, __u16 min, __u16 max)
{
	struct ipv4_prefix prefix;
	struct port_range ports;

	prefix.address.s_addr = cpu_to_be32(addr);
	prefix.len = prefix_len;
	ports.min = min;
	ports.max = max;

	return assert_equals_int(0, pool4db_rm(1, prefix, &ports), "rm");
}

static bool add_common_samples(void)
{
	if (!add(0xc0000200U, 31, 6, 7)) /* 192.0.2.0/31 (6-7) */
		return false;
	if (!add(0xc0000210U, 32, 15, 18)) /* 192.0.2.16 (15-18) */
		return false;
	if (!add(0xc0000220U, 30, 1, 1)) /* 192.0.2.32/30 (1-1) */
		return false;
	if (!add(0xc0000210U, 32, 22, 23)) /* 192.0.2.16 (22-23) */
		return false;
	if (!add(0xc0000210U, 31, 19, 19)) /* 192.0.2.16/31 (19-19) */
		return false;

	return true;
}

/**
 * init_taddr - Boilerplate code to initialize a transport address during the
 * tests.
 */
static void init_taddr(struct ipv4_transport_addr *taddr, __u32 addr, __u16 port)
{
	taddr->l3.s_addr = cpu_to_be32(addr);
	taddr->l4 = port;
}

struct foreach_taddr4_args {
	struct ipv4_transport_addr *expected;
	unsigned int expected_len;
	unsigned int i;
};

static int validate_taddr4(struct ipv4_transport_addr *addr, void *void_args)
{
	struct foreach_taddr4_args *args = void_args;
	bool success = true;

	/* log_debug("foreaching %pI4:%u", &addr->l3, addr->l4); */

	success &= assert_true(args->i < args->expected_len, "iteration limit");
	if (!success)
		return -EINVAL;

	success &= assert_equals_ipv4(&args->expected[args->i].l3, &addr->l3, "addr");
	success &= assert_equals_u16(args->expected[args->i].l4, addr->l4, "port");

	args->i++;
	return success ? 0 : -EINVAL;
}

static bool test_foreach_taddr4(void)
{
	const unsigned int COUNT = 16;
	struct ipv4_transport_addr expected[2 * COUNT];
	unsigned int i = 0;
	struct foreach_taddr4_args args;
	int error;
	bool success = true;

	if (!add_common_samples())
		return false;

	/* 192.0.2.0/31 (6-7) */
	init_taddr(&expected[i++], 0xc0000200, 6);
	init_taddr(&expected[i++], 0xc0000200, 7);
	init_taddr(&expected[i++], 0xc0000201, 6);
	init_taddr(&expected[i++], 0xc0000201, 7);

	/* 192.0.2.16 (15-19, 22-23) */
	init_taddr(&expected[i++], 0xc0000210, 22);
	init_taddr(&expected[i++], 0xc0000210, 23);
	init_taddr(&expected[i++], 0xc0000210, 15);
	init_taddr(&expected[i++], 0xc0000210, 16);
	init_taddr(&expected[i++], 0xc0000210, 17);
	init_taddr(&expected[i++], 0xc0000210, 18);
	init_taddr(&expected[i++], 0xc0000210, 19);

	/*
	 * As you can see, the order of the transport addresses is not entirely
	 * intuitive, but we're good as long as it groups them by address and
	 * the foreach never revisits.
	 */

	/* 192.0.2.32/30 (1) */
	init_taddr(&expected[i++], 0xc0000220, 1);
	init_taddr(&expected[i++], 0xc0000221, 1);
	init_taddr(&expected[i++], 0xc0000222, 1);
	init_taddr(&expected[i++], 0xc0000223, 1);

	/* 192.0.2.17 (19) */
	init_taddr(&expected[i++], 0xc0000211, 19);

	if (i != COUNT) {
		log_err("Input mismatch. Unit test is broken: %u %u", i, COUNT);
		return false;
	}

	/*
	 * This simulates wrap-arounding without having to reinit the array for
	 * every test.
	 */
	memcpy(&expected[COUNT], &expected[0], COUNT * sizeof(*expected));

	for (i = 0; i < 3 * COUNT; i++) {
		args.expected = &expected[i % COUNT];
		args.expected_len = COUNT;
		args.i = 0;
		error = pool4db_foreach_taddr4(1, validate_taddr4, &args, i);
		success &= assert_equals_int(0, error, "call");
		/* log_debug("--------------"); */
	}

	return success;
}

static void init_sample(struct pool4_sample *sample, __u32 addr, __u16 min,
		__u16 max)
{
	sample->addr.s_addr = cpu_to_be32(addr);
	sample->range.min = min;
	sample->range.max = max;
}

struct foreach_sample_args {
	struct pool4_sample *expected;
	unsigned int expected_len;
	unsigned int i;
};

static int validate_sample(struct pool4_sample *sample, void *void_args)
{
	struct foreach_sample_args *args = void_args;
	bool success = true;

	/* log_debug("foreaching %pI4 %u-%u", &sample->addr, sample->range.min,
			sample->range.max); */

	success &= assert_true(args->i < args->expected_len, "iteration limit");
	if (!success)
		return -EINVAL;

	success &= assert_equals_ipv4(&args->expected[args->i].addr,
			&sample->addr, "addr");
	success &= assert_equals_u16(args->expected[args->i].range.min,
			sample->range.min, "min");
	success &= assert_equals_u16(args->expected[args->i].range.max,
			sample->range.max, "max");

	args->i++;
	return success ? 0 : -EINVAL;
}

static bool test_foreach_sample(void)
{
	const unsigned int COUNT = 9;
	struct pool4_sample expected[COUNT];
	unsigned int i = 0;
	struct foreach_sample_args args;
	int error;
	bool success = true;

	if (!add_common_samples())
		return false;

	init_sample(&expected[i++], 0xc0000200U, 6, 7);
	init_sample(&expected[i++], 0xc0000201U, 6, 7);
	init_sample(&expected[i++], 0xc0000210U, 22, 23);
	init_sample(&expected[i++], 0xc0000210U, 15, 19);
	init_sample(&expected[i++], 0xc0000220U, 1, 1);
	init_sample(&expected[i++], 0xc0000221U, 1, 1);
	init_sample(&expected[i++], 0xc0000222U, 1, 1);
	init_sample(&expected[i++], 0xc0000223U, 1, 1);
	init_sample(&expected[i++], 0xc0000211U, 19, 19);

	if (i != COUNT) {
		log_err("Input mismatch. Unit test is broken: %u %u", i, COUNT);
		return false;
	}

	args.expected = &expected[0];
	args.expected_len = COUNT;
	args.i = 0;
	error = pool4db_foreach_sample(1, validate_sample, &args, NULL);
	success &= assert_equals_int(0, error, "call");

	for (i = 0; i < COUNT; i++) {
		/* foreach sample skips offset. */
		args.expected = &expected[i + 1];
		args.expected_len = COUNT - i - 1;
		args.i = 0;
		error = pool4db_foreach_sample(1, validate_sample, &args,
				&expected[i]);
		success &= assert_equals_int(0, error, "call");
		/* log_debug("--------------"); */
	}

	return success;
}

/**
 * assert_contains_range - "assert 192.0.2.@addr_min - 192.0.2.@add_max on
 * ports @port_min through @port_max belong to the pool (@expected true) or not
 * (@expected false)."
 */
static bool assert_contains_range(__u32 addr_min, __u32 addr_max,
		__u16 port_min, __u16 port_max, bool expected)
{
	struct ipv4_transport_addr taddr;
	__u32 i;
	bool result;
	bool success = true;

	for (i = addr_min; i < addr_max; i++) {
		taddr.l3.s_addr = cpu_to_be32(0xc0000200U | i);
		for (taddr.l4 = port_min; taddr.l4 < port_max; taddr.l4++) {
			result = pool4db_contains(1, &taddr);
			success &= assert_bool(expected, result, "contains");
			result = pool4db_contains_all(&taddr);
			success &= assert_bool(expected, result, "all");
		}
	}

	return success;
}

/**
 * test_flow - mainly tests rm, contains and contains_all at the same time.
 */
static bool test_flow(void)
{
	unsigned int i;
	bool success = true;

	/* ---------------------------------------------------------- */

	if (!add(0xc0000210U, 29, 10, 20)) /* 192.0.2.16-23 (10-20) */
		return false;
	if (!add(0xc0000211U, 32, 30, 40)) /* 192.0.2.17 (30-40) */
		return false;

	success &= assert_contains_range(0, 15, 0, 30, false);
	success &= assert_contains_range(16, 23, 0, 10, false);
	success &= assert_contains_range(16, 23, 10, 20, true);
	success &= assert_contains_range(16, 23, 20, 30, false);
	success &= assert_contains_range(24, 32, 0, 50, false);

	/* ---------------------------------------------------------- */

	/* Remove the exact existing port ranges of multiple addresses. */
	if (!rm(0xc0000212U, 31, 10, 20)) /* 192.0.2.18-23 (10-20) */
		return false;

	test = 0xc000020FU; /* 192.0.2.15 */
	success &= assert_contains_range(test, 0, 30, false);
	for (i = 0; i < 2; i++) {
		test++; /* 192.0.2.16-17 */
		success &= assert_contains_range(test, 0, 10, false);
		success &= assert_contains_range(test, 10, 20, true);
		success &= assert_contains_range(test, 20, 30, false);
	}
	for (i = 0; i < 2; i++) {
		test++; /* 192.0.2.18-19 */
		success &= assert_contains_range(test, 0, 30, false);
	}
	for (i = 0; i < 4; i++) {
		test++; /* 192.0.2.20-23 */
		success &= assert_contains_range(test, 0, 10, false);
		success &= assert_contains_range(test, 10, 20, true);
		success &= assert_contains_range(test, 20, 30, false);
	}
	test++; /* 192.0.2.24 */
	success &= assert_contains_range(test, 0, 30, false);

	/* ---------------------------------------------------------- */

	/* Remove existing port ranges of multiple addresses. */
	if (!rm(0xc0000214U, 30, 0, 65535)) /* 192.0.2.20/30 (0-65535) */
		return false;

	test = 0xc000020FU; /* 192.0.2.15 */
	success &= assert_contains_range(test, 0, 30, false);
	for (i = 0; i < 2; i++) {
		test++; /* 192.0.2.16-17 */
		success &= assert_contains_range(test, 0, 10, false);
		success &= assert_contains_range(test, 10, 20, true);
		success &= assert_contains_range(test, 20, 30, false);
	}
	for (i = 0; i < 7; i++) {
		test++; /* 192.0.2.18-24 */
		success &= assert_contains_range(test, 0, 30, false);
	}

	/* ---------------------------------------------------------- */

	/* Remove exactly a lower fraction of a port range. */
	if (!rm(0xc0000210U, 32, 10, 13)) /* 192.0.2.16/32 (10-13) */
		return false;

	test = 0xc000020FU; /* 192.0.2.15 */
	success &= assert_contains_range(test, 0, 30, false);
	test++; /* 192.0.2.16 */
	success &= assert_contains_range(test, 0, 13, false);
	success &= assert_contains_range(test, 13, 20, true);
	success &= assert_contains_range(test, 20, 30, false);
	test++; /* 192.0.2.17 */
	success &= assert_contains_range(test, 0, 10, false);
	success &= assert_contains_range(test, 10, 20, true);
	success &= assert_contains_range(test, 20, 30, false);
	for (i = 0; i < 7; i++) {
		test++; /* 192.0.2.18-24 */
		success &= assert_contains_range(test, 0, 30, false);
	}

	/* ---------------------------------------------------------- */

	/* Remove exactly an upper fraction of a port range. */
	if (!rm(0xc0000210U, 32, 17, 20)) /* 192.0.2.16/32 (17-20) */
		return false;

	test = 0xc000020FU; /* 192.0.2.15 */
	success &= assert_contains_range(test, 0, 30, false);
	test++; /* 192.0.2.16 */
	success &= assert_contains_range(test, 0, 13, false);
	success &= assert_contains_range(test, 13, 16, true);
	success &= assert_contains_range(test, 16, 30, false);
	test++; /* 192.0.2.17 */
	success &= assert_contains_range(test, 0, 10, false);
	success &= assert_contains_range(test, 10, 20, true);
	success &= assert_contains_range(test, 20, 30, false);
	for (i = 0; i < 7; i++) {
		test++; /* 192.0.2.18-24 */
		success &= assert_contains_range(test, 0, 30, false);
	}

	/* ---------------------------------------------------------- */


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
	INIT_CALL_END(init(), test_foreach_taddr4(), destroy(), "Taddr foreach");
	INIT_CALL_END(init(), test_foreach_sample(), destroy(), "Sample foreach");
	INIT_CALL_END(init(), test_flow(), destroy(), "Flow");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
