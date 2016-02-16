#include <linux/module.h>
#include "nat64/unit/unit_test.h"
#include "session/table.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Session table module test.");

static struct session_table table;
#define TEST_SESSION_COUNT 9
static struct session_entry *entries[TEST_SESSION_COUNT];

static bool inject(unsigned int index, __u32 local4addr, __u16 local4id,
		__u32 remote4addr, __u16 remote4id)
{
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;
	int error;

	remote6.l3.s6_addr32[0] = cpu_to_be32(0x20010db8u);
	remote6.l3.s6_addr32[1] = 0;
	remote6.l3.s6_addr32[2] = 0;
	remote6.l3.s6_addr32[3] = cpu_to_be32(local4addr);
	remote6.l4 = local4id;
	local6.l3.s6_addr32[0] = cpu_to_be32(0x0064ff9bu);
	local6.l3.s6_addr32[1] = 0;
	local6.l3.s6_addr32[2] = 0;
	local6.l3.s6_addr32[3] = cpu_to_be32(0xc0000200u | remote4addr);
	local6.l4 = remote4id;

	local4.l3.s_addr = cpu_to_be32(0xcb007100u | local4addr);
	local4.l4 = local4id;
	remote4.l3.s_addr = cpu_to_be32(0xc0000200u | remote4addr);
	remote4.l4 = remote4id;

	entries[index] = session_create(&remote6, &local6, &local4, &remote4,
			L4PROTO_UDP, NULL);
	if (!entries[index])
		return false;

	error = sessiontable_add(&table, entries[index], NULL, NULL);
	if (error) {
		log_err("Errcode %d on sessiontable_add.", error);
		session_put(entries[index], true);
		return false;
	}

	session_put(entries[index], false);
	return true;
}

static bool insert_test_sessions(void)
{
	/*
	 * Notice:
	 * This whole file currently only intends to test the foreach function.
	 * Other functions are better covered in the Session DB test.
	 *
	 * However, I'm also adding noise to the add function because it's free:
	 *
	 * This should be every combination needed to test sessiontable_add()
	 * sorts by local transport address, then by remote transport address.
	 * (Though the test only covers IPv4 order.)
	 * Also,
	 * the insertion order is random; it doesn't have any purpose other
	 * than tentatively messing with the add function.
	 */
	return inject(1, 2, 100, 3, 1300)
			&& inject(6, 2, 200, 3, 1100)
			&& inject(3, 2, 200, 2, 1100)
			&& inject(7, 2, 300, 1, 1100)
			&& inject(0, 1, 300, 3, 1300)
			&& inject(8, 3, 100, 1, 1100)
			&& inject(4, 2, 200, 2, 1200)
			&& inject(2, 2, 200, 1, 1300)
			&& inject(5, 2, 200, 2, 1300);
}

struct unit_iteration_args {
	unsigned int i;
	unsigned int offset;
};

static int cb(struct session_entry *session, void *void_args)
{
	struct unit_iteration_args *args = void_args;
	unsigned int index;
	bool success = true;

	index = args->offset + args->i;
	success &= ASSERT_BOOL(true, index < TEST_SESSION_COUNT, "overflow");
	if (success)
		success &= ASSERT_SESSION(entries[index], session, "Session");

	args->i++;
	return success ? 0 : -EINVAL;
}

static bool test_foreach(void)
{
	struct ipv4_transport_addr local;
	struct ipv4_transport_addr remote;
	struct unit_iteration_args args;
	int error;
	bool success = true;

	local.l3.s_addr = cpu_to_be32(0xcb007102u); /* 203.0.113.2 */
	local.l4 = 200;
	remote.l3.s_addr = cpu_to_be32(0xc0000202u); /* 192.0.2.2 */
	remote.l4 = 1200;

	/* Empty table, no offset. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, NULL, NULL, 0);
	success &= ASSERT_INT(0, error, "call 1 result");
	success &= ASSERT_UINT(0, args.i, "call 1 counter");

	/* Empty table, offset, include offset, offset not found. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, &remote, &local, true);
	success &= ASSERT_INT(0, error, "call 2 result");
	success &= ASSERT_UINT(0, args.i, "call 2 counter");

	/* Empty table, offset, do not include offset, offset not found. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, &remote, &local, false);
	success &= ASSERT_INT(0, error, "call 3 result");
	success &= ASSERT_UINT(0, args.i, "call 3 counter");

	/* ----------------------------------- */

	if (!insert_test_sessions())
		return false;

	/* Populated table, no offset. */
	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, NULL, NULL, 0);
	success &= ASSERT_INT(0, error, "call 4 result");
	success &= ASSERT_UINT(9, args.i, "call 4 counter");

	/* Populated table, offset, include offset, offset found. */
	args.i = 0;
	args.offset = 4;
	error = __foreach(&table, cb, &args, &remote, &local, true);
	success &= ASSERT_INT(0, error, "call 5 result");
	success &= ASSERT_UINT(5, args.i, "call 5 counter");

	/* Populated table, offset, include offset, offset not found. */
	args.i = 0;
	args.offset = 5;
	remote.l4 = 1250;
	error = __foreach(&table, cb, &args, &remote, &local, true);
	success &= ASSERT_INT(0, error, "call 6 result");
	success &= ASSERT_UINT(4, args.i, "call 6 counter");

	/* Populated table, offset, do not include offset, offset found. */
	args.i = 0;
	args.offset = 5;
	remote.l4 = 1200;
	error = __foreach(&table, cb, &args, &remote, &local, false);
	success &= ASSERT_INT(0, error, "call 7 result");
	success &= ASSERT_UINT(4, args.i, "call 7 counter");

	/* Populated table, offset, do not include offset, offset not found. */
	args.i = 0;
	args.offset = 5;
	remote.l4 = 1250;
	error = __foreach(&table, cb, &args, &remote, &local, false);
	success &= ASSERT_INT(0, error, "call 8 result");
	success &= ASSERT_UINT(4, args.i, "call 8 counter");

	/* ----------------------------------- */

	/* Offset is before first, include offset. */
	local.l3.s_addr = cpu_to_be32(0xcb007101u); /* 203.0.113.1 */
	local.l4 = 300;
	remote.l3.s_addr = cpu_to_be32(0xc0000203u); /* 192.0.2.3 */
	remote.l4 = 1200;

	args.i = 0;
	args.offset = 0;
	error = __foreach(&table, cb, &args, &remote, &local, true);
	success &= ASSERT_INT(0, error, "call 9 result");
	success &= ASSERT_UINT(9, args.i, "call 9 counter");

	/* Offset is before first, do not include offset. */
	args.i = 0;
	error = __foreach(&table, cb, &args, &remote, &local, false);
	success &= ASSERT_INT(0, error, "call 10 result");
	success &= ASSERT_UINT(9, args.i, "call 10 counter");

	/* Offset is first, include offset. */
	remote.l4 = 1300;

	args.i = 0;
	error = __foreach(&table, cb, &args, &remote, &local, true);
	success &= ASSERT_INT(0, error, "call 11 result");
	success &= ASSERT_UINT(9, args.i, "call 11 counter");

	/* Offset is first, do not include offset. */
	args.i = 0;
	args.offset = 1;
	error = __foreach(&table, cb, &args, &remote, &local, false);
	success &= ASSERT_INT(0, error, "call 12 result");
	success &= ASSERT_UINT(8, args.i, "call 12 counter");

	/* Offset is last, include offset. */
	local.l3.s_addr = cpu_to_be32(0xcb007103u); /* 203.0.113.3 */
	local.l4 = 100;
	remote.l3.s_addr = cpu_to_be32(0xc0000201u); /* 192.0.2.1 */
	remote.l4 = 1100;

	args.i = 0;
	args.offset = 8;
	error = __foreach(&table, cb, &args, &remote, &local, true);
	success &= ASSERT_INT(0, error, "call 13 result");
	success &= ASSERT_UINT(1, args.i, "call 13 counter");

	/* Offset is last, do not include offset. */
	args.i = 0;
	error = __foreach(&table, cb, &args, &remote, &local, false);
	success &= ASSERT_INT(0, error, "call 14 result");
	success &= ASSERT_UINT(0, args.i, "call 14 counter");

	/* Offset is after last, include offset. */
	remote.l4 = 1200;

	args.i = 0;
	error = __foreach(&table, cb, &args, &remote, &local, true);
	success &= ASSERT_INT(0, error, "call 15 result");
	success &= ASSERT_UINT(0, args.i, "call 15 counter");

	/* Offset is after last, do not include offset. */
	args.i = 0;
	error = __foreach(&table, cb, &args, &remote, &local, false);
	success &= ASSERT_INT(0, error, "call 16 result");
	success &= ASSERT_UINT(0, args.i, "call 16 counter");

	return success;
}

static enum session_fate just_die(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static bool init(void)
{
	if (session_init())
		return false;
	sessiontable_init(&table, UDP_DEFAULT, just_die, 0, NULL);
	return true;
}

static void end(void)
{
	sessiontable_destroy(&table);
	session_destroy();
}

int init_module(void)
{
	START_TESTS("Session table");

	INIT_CALL_END(init(), test_foreach(), end(), "Foreach");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
