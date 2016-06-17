#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/stateful/session/table4.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("IPv4 session index test.");

static void init_session(struct session_entry *session,
		char *src4_addr, u16 src4_id,
		char *dst4_addr, u16 dst4_id)
{
	memset(&session->src6, 0, sizeof(session->src6));
	memset(&session->dst6, 0, sizeof(session->dst6));

	if (str_to_addr4(src4_addr, &session->src4.l3))
		return;
	session->src4.l4 = src4_id;
	if (str_to_addr4(dst4_addr, &session->dst4.l3))
		return;
	session->dst4.l4 = dst4_id;
}

struct session_table4 *table;
struct session_entry sessions[20];

static bool try_add(int i,
		char *src4_addr, u16 src4_id,
		char *dst4_addr, u16 dst4_id)
{
	init_session(&sessions[i], src4_addr, src4_id, dst4_addr, dst4_id);
	return ASSERT_INT(0, st4_add(table, &sessions[i]), "add errcode");
}

bool improvised_test(void)
{
	int i = 0;
	bool success = true;

	table = st4_create();
	if (!table) {
		pr_err("table is NULL");
		return false;
	}

//	success = try_add(i++, "0.0.0.5", 5, "0.0.0.1", 1);
//	success = try_add(i++, "0.0.0.6", 6, "0.0.0.1", 1);
//	success = try_add(i++, "0.0.0.4", 4, "0.0.0.1", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.1", 1);
//
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.2", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.3", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.4", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.5", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.6", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.7", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.8", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.9", 1);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 1);
//
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 2);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 3);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 4);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 5);
//	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 6);

//	/* ---------------------- */
//	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
//	success = try_add(i++, "0.0.0.2", 5, "0.0.0.1", 1);
//	success = try_add(i++, "0.0.0.3", 5, "0.0.0.1", 1);
//	st4_print(table);
//
//	success = ASSERT_INT(0, st4_rm(table, &sessions[0]), "1st rm");
//	st4_print(table);
//
//	/* ---------------------- */
//	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
//	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 12);
//	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 13);
//	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 14);
//	st4_print(table);
//
//	success = ASSERT_INT(0, st4_rm(table, &sessions[3]), "2nd rm");
//	st4_print(table);

	/* ---------------------- */
	st4_flush(table);
	i = 0;

	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
	success = try_add(i++, "0.0.0.1", 5, "0.0.0.2", 1);
	st4_print(table);

	st4_rm(table, &sessions[1]);
	st4_print(table);

	/* ---------------------- */
	st4_flush(table);
	i = 0;

	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 2);
	st4_print(table);

	st4_rm(table, &sessions[1]);
	st4_print(table);

	/* ---------------------- */
	st4_flush(table);
	i = 0;

	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
	success = try_add(i++, "0.0.0.1", 5, "0.0.0.2", 1);
	success = try_add(i++, "0.0.0.1", 5, "0.0.0.2", 2);
	st4_print(table);

	st4_rm(table, &sessions[2]);
	st4_print(table);

	/* ---------------------- */
	st4_destroy(table);
	pr_info("i = %u\n", i);
	return success;
}

int init_module(void)
{
	START_TESTS("IPv4 session index");

	CALL_TEST(improvised_test(), "meh");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
