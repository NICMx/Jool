#include <linux/module.h>
#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/config.h"
#include "bib/table.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("BIB table module test.");

struct bib_table table;
#define TEST_BIB_COUNT 5
struct bib_entry *entries[TEST_BIB_COUNT];

static bool inject(unsigned int index, char *addr4, u16 port4,
		char *addr6, u16 port6)
{
	struct ipv4_transport_addr taddr4;
	struct ipv6_transport_addr taddr6;
	int error;

	if (str_to_addr4(addr4, &taddr4.l3))
		return false;
	if (str_to_addr6(addr6, &taddr6.l3))
		return false;
	taddr4.l4 = port4;
	taddr6.l4 = port6;

	entries[index] = bibentry_create(&taddr4, &taddr6, false, L4PROTO_UDP);
	if (!entries[index]) {
		log_err("Could not allocate entry %u.", index);
		return false;
	}

	error = bibtable_add(&table, entries[index]);
	if (error) {
		log_err("Errcode %d on BIB table add %u.", error, index);
		return false;
	}

	return true;
}

static bool insert_test_bibs(void)
{
	return inject(0, "192.0.2.1", 100, "2001:db8::1", 100)
			&& inject(1, "192.0.2.2", 50, "2001:db8::2", 50)
			&& inject(2, "192.0.2.2", 100, "2001:db8::2", 100)
			&& inject(3, "192.0.2.2", 150, "2001:db8::2", 150)
			&& inject(4, "192.0.2.3", 100, "2001:db8::3", 100);
}

struct unit_iteration_args {
	unsigned int i;
	unsigned int offset;
};

static int cb(struct bib_entry *bib, void *void_args)
{
	struct unit_iteration_args *args = void_args;
	unsigned int index;
	bool success = true;

	index = args->offset + args->i;
	success &= ASSERT_BOOL(true, index < TEST_BIB_COUNT, "overflow");
	if (success)
		success &= ASSERT_BIB(entries[index], bib, "Bib");

	args->i++;
	return success ? 0 : -EINVAL;
}

static bool test_foreach(void)
{
	struct ipv4_transport_addr offset;
	struct unit_iteration_args args;
	int error;
	bool success = true;

	offset.l3.s_addr = cpu_to_be32(0xc0000202u); /* 192.0.2.2 */
	offset.l4 = 100;

	/* Empty table, no offset. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, NULL, 0);
	success &= ASSERT_INT(0, error, "call 1 result");
	success &= ASSERT_UINT(0, args.i, "call 1 counter");

	/* Empty table, offset, include offset, offset not found. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, &offset, true);
	success &= ASSERT_INT(0, error, "call 2 result");
	success &= ASSERT_UINT(0, args.i, "call 2 counter");

	/* Empty table, offset, do not include offset, offset not found. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, &offset, false);
	success &= ASSERT_INT(0, error, "call 3 result");
	success &= ASSERT_UINT(0, args.i, "call 3 counter");

	/* ----------------------------------- */

	if (!insert_test_bibs())
		return false;

	/* Populated table, no offset. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, NULL, 0);
	success &= ASSERT_INT(0, error, "call 4 result");
	success &= ASSERT_UINT(5, args.i, "call 4 counter");

	/* Populated table, offset, include offset, offset found. */
	args.i = 0;
	args.offset = 2;
	error = __foreach(&table, cb, &args, &offset, true);
	success &= ASSERT_INT(0, error, "call 5 result");
	success &= ASSERT_UINT(3, args.i, "call 5 counter");

	/* Populated table, offset, include offset, offset not found. */
	args.i = 0;
	args.offset = 3;
	offset.l4 = 125;
	error = __foreach(&table, cb, &args, &offset, true);
	success &= ASSERT_INT(0, error, "call 6 result");
	success &= ASSERT_UINT(2, args.i, "call 6 counter");

	/* Populated table, offset, do not include offset, offset found. */
	args.i = 0;
	args.offset = 3;
	offset.l4 = 100;
	error = __foreach(&table, cb, &args, &offset, false);
	success &= ASSERT_INT(0, error, "call 7 result");
	success &= ASSERT_UINT(2, args.i, "call 7 counter");

	/* Populated table, offset, do not include offset, offset not found. */
	args.i = 0;
	args.offset = 3;
	offset.l4 = 125;
	error = __foreach(&table, cb, &args, &offset, false);
	success &= ASSERT_INT(0, error, "call 8 result");
	success &= ASSERT_UINT(2, args.i, "call 8 counter");

	/* ----------------------------------- */

	/* Offset is before first, include offset. */
	args.i = 0;
	args.offset = 0;
	offset.l3.s_addr = cpu_to_be32(0xc0000201u);
	offset.l4 = 50;
	error = __foreach(&table, cb, &args, &offset, true);
	success &= ASSERT_INT(0, error, "call 9 result");
	success &= ASSERT_UINT(5, args.i, "call 9 counter");

	/* Offset is before first, do not include offset. */
	args.i = 0;
	error = __foreach(&table, cb, &args, &offset, false);
	success &= ASSERT_INT(0, error, "call 10 result");
	success &= ASSERT_UINT(5, args.i, "call 10 counter");

	/* Offset is first, include offset. */
	args.i = 0;
	offset.l4 = 100;
	error = __foreach(&table, cb, &args, &offset, true);
	success &= ASSERT_INT(0, error, "call 11 result");
	success &= ASSERT_UINT(5, args.i, "call 11 counter");

	/* Offset is first, do not include offset. */
	args.i = 0;
	args.offset = 1;
	error = __foreach(&table, cb, &args, &offset, false);
	success &= ASSERT_INT(0, error, "call 12 result");
	success &= ASSERT_UINT(4, args.i, "call 12 counter");

	/* Offset is last, include offset. */
	args.i = 0;
	args.offset = 4;
	offset.l3.s_addr = cpu_to_be32(0xc0000203u);
	offset.l4 = 100;
	error = __foreach(&table, cb, &args, &offset, true);
	success &= ASSERT_INT(0, error, "call 13 result");
	success &= ASSERT_UINT(1, args.i, "call 13 counter");

	/* Offset is last, do not include offset. */
	args.i = 0;
	error = __foreach(&table, cb, &args, &offset, false);
	success &= ASSERT_INT(0, error, "call 14 result");
	success &= ASSERT_UINT(0, args.i, "call 14 counter");

	/* Offset is after last, include offset. */
	args.i = 0;
	offset.l4 = 150;
	error = __foreach(&table, cb, &args, &offset, true);
	success &= ASSERT_INT(0, error, "call 15 result");
	success &= ASSERT_UINT(0, args.i, "call 15 counter");

	/* Offset is after last, do not include offset. */
	args.i = 0;
	error = __foreach(&table, cb, &args, &offset, false);
	success &= ASSERT_INT(0, error, "call 16 result");
	success &= ASSERT_UINT(0, args.i, "call 16 counter");

	return success;
}

static bool init(void)
{
	if (config_init(false))
		return false;
	if (bibentry_init()) {
		config_destroy();
		return false;
	}
	bibtable_init(&table);

	return true;
}

static void end(void)
{
	bibtable_destroy(&table);
	bibentry_destroy();
	config_destroy();
}

int init_module(void)
{
	START_TESTS("BIB table");

	INIT_CALL_END(init(), test_foreach(), end(), "Foreach");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
