#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/stateful/session/table4.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("IPv4 session index test.");

static void init_session(struct session_entry *session,
		const char *saddr, const u16 sport,
		const char *daddr, const u16 dport)
{
	memset(session, 0, sizeof(*session));

	if (str_to_addr4(saddr, &session->src4.l3))
		return;
	session->src4.l4 = sport;
	if (str_to_addr4(daddr, &session->dst4.l3))
		return;
	session->dst4.l4 = dport;

	session->l4_proto = L4PROTO_UDP; /* Whatever */
}

struct session_table4 *table;
struct session_entry sessions[50];
unsigned int s = 0;

//static bool try_add(int i,
//		char *src4_addr, u16 src4_id,
//		char *dst4_addr, u16 dst4_id)
//{
//	init_session(&sessions[i], src4_addr, src4_id, dst4_addr, dst4_id);
//	return ASSERT_INT(0, st4_add(table, &sessions[i]), "add errcode");
//}
//
//bool improvised_test(void)
//{
//	int i = 0;
//	bool success = true;
//
//	table = st4_create();
//	if (!table) {
//		pr_err("table is NULL");
//		return false;
//	}
//
////	success = try_add(i++, "0.0.0.5", 5, "0.0.0.1", 1);
////	success = try_add(i++, "0.0.0.6", 6, "0.0.0.1", 1);
////	success = try_add(i++, "0.0.0.4", 4, "0.0.0.1", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.1", 1);
////
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.2", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.3", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.4", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.5", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.6", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.7", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.8", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.9", 1);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 1);
////
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 2);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 3);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 4);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 5);
////	success = try_add(i++, "0.0.0.3", 3, "0.0.0.10", 6);
//
////	/* ---------------------- */
////	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
////	success = try_add(i++, "0.0.0.2", 5, "0.0.0.1", 1);
////	success = try_add(i++, "0.0.0.3", 5, "0.0.0.1", 1);
////	st4_print(table);
////
////	success = ASSERT_INT(0, st4_rm(table, &sessions[0]), "1st rm");
////	st4_print(table);
////
////	/* ---------------------- */
////	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
////	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 12);
////	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 13);
////	success = try_add(i++, "0.0.0.1", 5, "0.0.0.1", 14);
////	st4_print(table);
////
////	success = ASSERT_INT(0, st4_rm(table, &sessions[3]), "2nd rm");
////	st4_print(table);
//
//	/* ---------------------- */
//	st4_flush(table);
//	i = 0;
//
//	success &= try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
//	success &= try_add(i++, "0.0.0.1", 5, "0.0.0.2", 1);
//	st4_print(table);
//
//	st4_rm(table, &sessions[1]);
//	st4_print(table);
//
//	/* ---------------------- */
//	st4_flush(table);
//	i = 0;
//
//	success &= try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
//	success &= try_add(i++, "0.0.0.1", 5, "0.0.0.1", 2);
//	st4_print(table);
//
//	st4_rm(table, &sessions[1]);
//	st4_print(table);
//
//	/* ---------------------- */
//	st4_flush(table);
//	i = 0;
//
//	success &= try_add(i++, "0.0.0.1", 5, "0.0.0.1", 1);
//	success &= try_add(i++, "0.0.0.1", 5, "0.0.0.2", 1);
//	success &= try_add(i++, "0.0.0.1", 5, "0.0.0.2", 2);
//	st4_print(table);
//
//	st4_rm(table, &sessions[2]);
//	st4_print(table);
//
//	/* ---------------------- */
//	st4_destroy(table);
//	pr_info("i = %u\n", i);
//	return success;
//}

static bool add(unsigned int i)
{
	return ASSERT_INT(0, st4_add(table, &sessions[i]), "add errcode");
}

struct find_test {
	int errcode;
	bool allow;
	struct session_entry *session;
};

struct find_test expecteds[8];

static void init_expected(unsigned int i, int errcode, bool allow,
		struct session_entry *session)
{
	expecteds[i].errcode = errcode;
	expecteds[i].allow = allow;
	expecteds[i].session = session;
}

static bool test_expecteds(void)
{
	unsigned int i;
	struct tuple tuple4 = {
			.l3_proto = L3PROTO_IPV4,
			.l4_proto = L4PROTO_UDP,
	};
	struct bib_entry bib;
	struct session_entry *session;
	bool allow;
	int error;
	bool success = true;

	for (i = 0; i < 8; i++) {
		tuple4.src.addr4 = sessions[i].dst4;
		tuple4.dst.addr4 = sessions[i].src4;
		error = st4_find_full(table, &tuple4, &bib, &session, &allow);

		success &= ASSERT_INT(expecteds[i].errcode, error, "errcode");
		if (!error) {
			success &= ASSERT_TADDR6(&sessions[i].src6, &bib.ipv6, "bib6");
			success &= ASSERT_TADDR4(&sessions[i].src4, &bib.ipv4, "bib4");
			success &= ASSERT_INT(L4PROTO_UDP, bib.l4_proto, "bib-l4");
			success &= ASSERT_PTR(expecteds[i].session, session, "session");
			success &= ASSERT_BOOL(expecteds[i].allow, allow, "allow");
		}
	}

	return success;
}

static bool findadd_test(void)
{
	unsigned int i;
	bool success = true;

	/* Empty DB */
	init_session(&sessions[0], "1.1.1.1", 1111, "5.5.5.5", 5555);
	/* Node is L1 */
	init_session(&sessions[1], "2.2.2.2", 2222, "5.5.5.5", 5555);
	/* Node is L2, parent has no L2 */
	init_session(&sessions[2], "1.1.1.1", 1111, "6.6.6.6", 6666);
	/* Node is L2, parent has L2 */
	init_session(&sessions[3], "1.1.1.1", 1111, "7.7.7.7", 7777);
	/* Node is L3, there is no L2 (parent is L1), L1 has no L3 */
	init_session(&sessions[4], "2.2.2.2", 2222, "5.5.5.5", 6666);
	/* Node is L3, there is no L2 (parent is L1), L1 has L3 */
	init_session(&sessions[5], "2.2.2.2", 2222, "5.5.5.5", 7777);
	/* Node is L3, there is L2 (parent is L2), L2 has no L3 */
	init_session(&sessions[6], "1.1.1.1", 1111, "6.6.6.6", 7777);
	/* Node is L3, there is L2 (parent is L2), L2 has L3 */
	init_session(&sessions[7], "1.1.1.1", 1111, "6.6.6.6", 8888);

	for (i = 0; i < 8; i++)
		init_expected(i, -ESRCH, false, NULL);

	success &= test_expecteds();

	success &= add(0);
	init_expected(0, 0, true, &sessions[0]);
	init_expected(2, 0, false, NULL);
	init_expected(3, 0, false, NULL);
	init_expected(6, 0, false, NULL);
	init_expected(7, 0, false, NULL);
	success &= test_expecteds();

	success &= add(1);
	init_expected(1, 0, true, &sessions[1]);
	init_expected(4, 0, true, NULL);
	init_expected(5, 0, true, NULL);
	success &= test_expecteds();

	success &= add(2);
	init_expected(2, 0, true, &sessions[2]);
	init_expected(6, 0, true, NULL);
	init_expected(7, 0, true, NULL);
	success &= test_expecteds();

	success &= add(3);
	init_expected(3, 0, true, &sessions[3]);
	success &= test_expecteds();

	success &= add(4);
	init_expected(4, 0, true, &sessions[4]);
	init_expected(5, 0, true, NULL);
	success &= test_expecteds();

	success &= add(5);
	init_expected(5, 0, true, &sessions[5]);
	success &= test_expecteds();

	success &= add(6);
	init_expected(6, 0, true, &sessions[6]);
	success &= test_expecteds();

	success &= add(7);
	init_expected(7, 0, true, &sessions[7]);
	success &= test_expecteds();

	/* st4_print(table); */
	st4_destroy(table);
	return success;
}

static bool add_session(const char *saddr, const __u16 sport,
		const char *daddr, const __u16 dport)
{
	bool result;

	if (s > ARRAY_SIZE(sessions)) {
		pr_err("Too many sessions.\n");
		return false;
	}

	init_session(&sessions[s], saddr, sport, daddr, dport);
	result = ASSERT_INT(0, st4_add(table, &sessions[s]), "add errcode");
	s++;

	return result;
}

static bool rm_session(const char *saddr, const __u16 sport,
		const char *daddr, const __u16 dport)
{
	struct session_entry session;
	unsigned int i;

	init_session(&session, saddr, sport, daddr, dport);

	for (i = 0; i < s; i++) {
		if (taddr4_equals(&sessions[i].src4, &session.src4)
				&& taddr4_equals(&sessions[i].dst4, &session.dst4)) {
			st4_rm(table, &sessions[i]);
			return true;
		}
	}

	pr_err("Session not found; the test is going to fail.\n");
	return false;
}

static void reset_rm_test(void)
{
	st4_print(table);
	st4_flush(table);
	s = 0;
}

/**
 * TODO I checked these visually; they aren't automated yet.
 */
static bool rm_test(void)
{
	const char *A = "192.0.2.8";
	const __u16 a = 1000;
	const char *B = "192.0.2.9";
	const __u16 b = 1100;
	const char *C = "192.0.2.10";
	const __u16 c = 1200;
	const char *L = "203.0.113.7";
	const __u16 l = 1900;
	const char *M = "203.0.113.8";
	const __u16 m = 2000;
	const char *N = "203.0.113.9";
	const __u16 n = 2100;
	const char *O = "203.0.113.10";
	const __u16 o = 2200;
	bool success = true;

	/* Node is L1 and has no subtrees */
	success &= add_session(A, a, M, m);
	st4_print(table);
	success &= rm_session(A, a, M, m);

	reset_rm_test();

	/* Node is L2 and has no subtrees */
	success &= add_session(A, a, M, m);
	success &= add_session(A, a, N, n);
	st4_print(table);
	success &= rm_session(A, a, N, n);

	reset_rm_test();

	/* Node is L3 (child of L1) and has no subtrees */
	success &= add_session(A, a, M, m);
	success &= add_session(A, a, M, n);
	st4_print(table);
	success &= rm_session(A, a, M, n);

	reset_rm_test();

	/* Node is L3 (child of L2) and has no subtrees */
	success &= add_session(A, a, M, m);
	success &= add_session(A, a, N, n);
	success &= add_session(A, a, N, o);
	st4_print(table);
	success &= rm_session(A, a, N, o);

	reset_rm_test();

	/* Node is L1, has all subtree types. */
	success &= add_session(B, b, M, m);
	success &= add_session(A, a, M, m); /* L1 - left */
	success &= add_session(B, b, N, n); /* L2 */
	success &= add_session(B, b, M, n); /* L3 */
	success &= add_session(C, c, M, m); /* L1 - right */
	st4_print(table);
	success &= rm_session(B, b, M, m);

	reset_rm_test();

	/* Node is L2, has all subtree types. */
	success &= add_session(A, a, L, m); /* parent; don't mind this one. */
	success &= add_session(A, a, N, n);
	success &= add_session(A, a, M, m); /* L2 - left */
	success &= add_session(A, a, N, o); /* L3 */
	success &= add_session(A, a, O, o); /* L2 - right */
	st4_print(table);
	success &= rm_session(A, a, N, n);

	reset_rm_test();

	/* Node is L3, has all subtree types. */

	success &= add_session(A, a, M, l); /* parent; don't mind this one. */
	success &= add_session(A, a, M, n);
	success &= add_session(A, a, M, m); /* L3 - left */
	success &= add_session(A, a, M, o); /* L3 - right */
	st4_print(table);
	success &= rm_session(A, a, M, n);

	reset_rm_test();

	return success;
}

static bool init(void)
{
	table = st4_create();
	return table;
}

static void destroy(void)
{
	st4_destroy(table);
}

int init_module(void)
{
	START_TESTS("IPv4 session index");

	INIT_CALL_END(init(), findadd_test(), destroy(), "findadd");
	INIT_CALL_END(init(), rm_test(), destroy(), "rm");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
