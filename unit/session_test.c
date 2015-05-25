#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/session.h"
#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "session/db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("Session module test.");

const l4_protocol PROTO = L4PROTO_UDP;
struct session_entry *sessions4[4][4][4][4];
struct session_entry *sessions6[4][4][4][4];

/*
#define SESSION_PRINT_KEY "session [%pI4#%u, %pI4#%u, %pI6c#%u, %pI6c#%u]"
#define PRINT_SESSION(session) \
	&session->remote4.l3, session->remote4.l4, \
	&session->local4.l3, session->local4.l4, \
	&session->local6.l3, session->local6.l4, \
	&session->remote6.l3, session->remote6.l4
*/

///**
// * Same as assert_bib(), except asserting session entries on the session table.
// */
//static bool assert_session(char* test_name, struct session_entry* session,
//		bool udp_table_has_it, bool tcp_table_has_it, bool icmp_table_has_it)
//{
//	struct session_entry *retrieved_session, *expected_session;
//	struct tuple tuple6, tuple4;
//	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
//	bool table_has_it[3];
//	bool success;
//	int i;
//
//	table_has_it[0] = udp_table_has_it;
//	table_has_it[1] = tcp_table_has_it;
//	table_has_it[2] = icmp_table_has_it;
//
//	for (i = 0; i < 3; i++) {
//		tuple4.dst.addr4 = session->local4;
//		tuple4.src.addr4 = session->remote4;
//		tuple4.l3_proto = L3PROTO_IPV4;
//		tuple4.l4_proto = l4_protos[i];
//
//		tuple6.dst.addr6 = session->local6;
//		tuple6.src.addr6 = session->remote6;
//		tuple6.l3_proto = L3PROTO_IPV6;
//		tuple6.l4_proto = l4_protos[i];
//
//		expected_session = table_has_it[i] ? session : NULL;
//		success = true;
//
//		retrieved_session = NULL;
//		success &= ASSERT_INT(table_has_it[i] ? 0 : -ESRCH,
//				sessiondb_get(&tuple4, NULL, &retrieved_session),
//				"%s", test_name);
//		success &= assert_session_entry_equals(expected_session, retrieved_session, test_name);
//
//		retrieved_session = NULL;
//		success &= ASSERT_INT(table_has_it[i] ? 0 : -ESRCH,
//				sessiondb_get(&tuple6, NULL, &retrieved_session),
//				"%s", test_name);
//		success &= assert_session_entry_equals(expected_session, retrieved_session, test_name);
//
//		if (!success)
//			return false;
//	}
//
//	return true;
//}

static bool assert4(unsigned int la, unsigned int lp,
		unsigned int ra, unsigned int rp)
{
	struct session_entry *session = NULL;
	struct tuple tuple4;
	bool success = true;

	tuple4.src.addr4.l3.s_addr = cpu_to_be32(0xcb007100 | ra);
	tuple4.src.addr4.l4 = rp;
	tuple4.dst.addr4.l3.s_addr = cpu_to_be32(0xc0000200 | la);
	tuple4.dst.addr4.l4 = lp;
	tuple4.l3_proto = L3PROTO_IPV4;
	tuple4.l4_proto = PROTO;

	if (sessions4[la][lp][ra][rp]) {
		success &= ASSERT_INT(0,
				sessiondb_get(&tuple4, NULL, &session),
				"get4 code - %u %u %u %u", la, lp, ra, rp);
		success &= ASSERT_SESSION(sessions4[la][lp][ra][rp], session,
				"get4 session");
	} else {
		success &= ASSERT_INT(-ESRCH,
				sessiondb_get(&tuple4, NULL, &session),
				"get4 code - %u %u %u %u", la, lp, ra, rp);
	}

	if (session)
		session_return(session);

	return success;
}

static bool assert6(unsigned int la, unsigned int lp,
		unsigned int ra, unsigned int rp)
{
	struct session_entry *session = NULL;
	struct tuple tuple6;
	bool success = true;

	tuple6.src.addr6.l3.s6_addr32[0] = cpu_to_be32(0x20010db8);
	tuple6.src.addr6.l3.s6_addr32[1] = 0;
	tuple6.src.addr6.l3.s6_addr32[2] = 0;
	tuple6.src.addr6.l3.s6_addr32[3] = cpu_to_be32(ra);
	tuple6.src.addr6.l4 = rp;
	tuple6.dst.addr6.l3.s6_addr32[0] = cpu_to_be32(0x00640000);
	tuple6.dst.addr6.l3.s6_addr32[1] = 0;
	tuple6.dst.addr6.l3.s6_addr32[2] = 0;
	tuple6.dst.addr6.l3.s6_addr32[3] = cpu_to_be32(la);
	tuple6.dst.addr6.l4 = lp;
	tuple6.l3_proto = L3PROTO_IPV6;
	tuple6.l4_proto = PROTO;

	if (sessions6[ra][rp][la][lp]) {
		success &= ASSERT_INT(0,
				sessiondb_get(&tuple6, NULL, &session),
				"get6 code - %u %u %u %u", ra, rp, la, lp);
		success &= ASSERT_SESSION(sessions6[ra][rp][la][lp], session,
				"get6 session");
	} else {
		success &= ASSERT_INT(-ESRCH,
				sessiondb_get(&tuple6, NULL, &session),
				"get6 code - %u %u %u %u", ra, rp, la, lp);
	}

	if (session)
		session_return(session);

	return success;
}

static bool test_db(void)
{
	unsigned int la; /* local addr */
	unsigned int lp; /* local port */
	unsigned int ra; /* remote addr */
	unsigned int rp; /* remote port */
	bool success = true;

	for (la = 0; la < 4; la++) {
		for (lp = 0; lp < 4; lp++) {
			for (ra = 0; ra < 4; ra++) {
				for (rp = 0; rp < 4; rp++) {
					success &= assert4(la, lp, ra, rp);
					success &= assert6(la, lp, ra, rp);
				}
			}
		}
	}

	return success;
}

static bool insert_test_sessions(void)
{
	struct session_entry *sessions[16];
	unsigned int i;

	memset(sessions4, 0, sizeof(sessions4));
	memset(sessions6, 0, sizeof(sessions6));

	sessions[0] = session_inject("2001:db8::1", 2, "64::2", 2, "192.0.2.2", 1, "203.0.113.2", 1, PROTO, true);
	sessions[1] = session_inject("2001:db8::1", 1, "64::2", 1, "192.0.2.2", 2, "203.0.113.2", 2, PROTO, true);
	sessions[2] = session_inject("2001:db8::2", 1, "64::2", 1, "192.0.2.2", 2, "203.0.113.1", 2, PROTO, true);
	sessions[3] = session_inject("2001:db8::2", 2, "64::2", 2, "192.0.2.2", 2, "203.0.113.1", 1, PROTO, true);
	sessions[4] = session_inject("2001:db8::1", 1, "64::2", 2, "192.0.2.1", 2, "203.0.113.2", 2, PROTO, true);
	sessions[5] = session_inject("2001:db8::2", 2, "64::1", 1, "192.0.2.2", 1, "203.0.113.1", 1, PROTO, true);
	sessions[6] = session_inject("2001:db8::2", 1, "64::1", 1, "192.0.2.1", 1, "203.0.113.2", 2, PROTO, true);
	sessions[7] = session_inject("2001:db8::1", 1, "64::1", 1, "192.0.2.2", 1, "203.0.113.2", 2, PROTO, true);
	sessions[8] = session_inject("2001:db8::2", 2, "64::1", 2, "192.0.2.1", 2, "203.0.113.1", 1, PROTO, true);
	sessions[9] = session_inject("2001:db8::1", 2, "64::1", 1, "192.0.2.2", 2, "203.0.113.2", 1, PROTO, true);
	sessions[10] = session_inject("2001:db8::2", 1, "64::1", 2, "192.0.2.2", 1, "203.0.113.1", 2, PROTO, true);
	sessions[11] = session_inject("2001:db8::1", 2, "64::1", 2, "192.0.2.1", 1, "203.0.113.2", 1, PROTO, true);
	sessions[12] = session_inject("2001:db8::2", 1, "64::2", 2, "192.0.2.1", 2, "203.0.113.2", 1, PROTO, true);
	sessions[13] = session_inject("2001:db8::1", 1, "64::1", 2, "192.0.2.1", 2, "203.0.113.1", 2, PROTO, true);
	sessions[14] = session_inject("2001:db8::1", 2, "64::2", 1, "192.0.2.1", 1, "203.0.113.1", 1, PROTO, true);
	sessions[15] = session_inject("2001:db8::2", 2, "64::2", 1, "192.0.2.1", 1, "203.0.113.1", 2, PROTO, true);
	for (i = 0; i < ARRAY_SIZE(sessions); i++) {
		if (!sessions[i]) {
			log_debug("Allocation failed in index %u.", i);
			return false;
		}
	}

	sessions6[1][2][2][2] = sessions4[2][1][2][1] = sessions[0];
	sessions6[1][1][2][1] = sessions4[2][2][2][2] = sessions[1];
	sessions6[2][1][2][1] = sessions4[2][2][1][2] = sessions[2];
	sessions6[2][2][2][2] = sessions4[2][2][1][1] = sessions[3];
	sessions6[1][1][2][2] = sessions4[1][2][2][2] = sessions[4];
	sessions6[2][2][1][1] = sessions4[2][1][1][1] = sessions[5];
	sessions6[2][1][1][1] = sessions4[1][1][2][2] = sessions[6];
	sessions6[1][1][1][1] = sessions4[2][1][2][2] = sessions[7];
	sessions6[2][2][1][2] = sessions4[1][2][1][1] = sessions[8];
	sessions6[1][2][1][1] = sessions4[2][2][2][1] = sessions[9];
	sessions6[2][1][1][2] = sessions4[2][1][1][2] = sessions[10];
	sessions6[1][2][1][2] = sessions4[1][1][2][1] = sessions[11];
	sessions6[2][1][2][2] = sessions4[1][2][2][1] = sessions[12];
	sessions6[1][1][1][2] = sessions4[1][2][1][2] = sessions[13];
	sessions6[1][2][2][1] = sessions4[1][1][1][1] = sessions[14];
	sessions6[2][2][2][1] = sessions4[1][1][1][2] = sessions[15];

	return test_db();
}

static bool simple_session(void)
{
	struct bib_entry bib = {
			.ipv4.l3.s_addr = cpu_to_be32(0xc0000201),
			.ipv4.l4 = 1,
			/*
			 * Session doesn't enfore remote6 x local4 uniqueness;
			 * that's BIB's responsibility.
			 * As a result, only the IPv4 side matters in the BIB
			 * foreach.
			 */
			.l4_proto = PROTO,
	};
	struct ipv6_prefix prefix6;
	struct ipv4_prefix prefix4;
	struct port_range ports;
	int error;
	bool success = true;

	if (!insert_test_sessions())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Deleting sessions by BIB.");
	error = sessiondb_delete_by_bib(&bib);
	success &= ASSERT_INT(0, error, "BIB delete result");

	sessions6[2][1][1][1] = sessions4[1][1][2][2] = NULL;
	sessions6[1][2][1][2] = sessions4[1][1][2][1] = NULL;
	sessions6[1][2][2][1] = sessions4[1][1][1][1] = NULL;
	sessions6[2][2][2][1] = sessions4[1][1][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Deleting again.");
	error = sessiondb_delete_by_bib(&bib);
	success &= ASSERT_INT(0, error, "BIB delete result");
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Deleting by prefix6.");
	prefix6.address.s6_addr32[0] = cpu_to_be32(0x00640000);
	prefix6.address.s6_addr32[1] = 0;
	prefix6.address.s6_addr32[2] = 0;
	prefix6.address.s6_addr32[3] = cpu_to_be32(1);
	prefix6.len = 128;
	ports.min = 0;
	ports.max = 5;
	sessiondb_delete_taddr6s(&prefix6);

	sessions6[2][2][1][1] = sessions4[2][1][1][1] = NULL;
	sessions6[1][1][1][1] = sessions4[2][1][2][2] = NULL;
	sessions6[2][2][1][2] = sessions4[1][2][1][1] = NULL;
	sessions6[1][2][1][1] = sessions4[2][2][2][1] = NULL;
	sessions6[2][1][1][2] = sessions4[2][1][1][2] = NULL;
	sessions6[1][1][1][2] = sessions4[1][2][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	return success;
}

//static bool test_address_filtering_aux(int src_addr_id, int src_port_id, int dst_addr_id,
//		int dst_port_id)
//{
//	struct tuple tuple4;
//
//	tuple4.src.addr4.l3 = addr4[src_addr_id].l3;
//	tuple4.dst.addr4.l3 = addr4[dst_addr_id].l3;
//	tuple4.src.addr4.l4 = addr4[src_port_id].l4;
//	tuple4.dst.addr4.l4 = addr4[dst_port_id].l4;
//	tuple4.l4_proto = L4PROTO_UDP;
//	tuple4.l3_proto = L3PROTO_IPV4;
//
//	log_tuple(&tuple4);
//	return sessiondb_allow(&tuple4);
//}
//
//static bool test_address_filtering(void)
//{
//	struct session_entry *session;
//	bool success = true;
//
//	/* Init. */
//	session = create_and_insert_session(0, 0, 0, 0);
//	if (!session)
//		return false;
//
//	/* Test the packet is allowed when the tuple and session match perfectly. */
//	success &= ASSERT_BOOL(true, test_address_filtering_aux(0, 0, 0, 0), "lol1");
//	/* Test a tuple that completely mismatches the session. */
//	success &= ASSERT_BOOL(false, test_address_filtering_aux(1, 1, 1, 1), "lol2");
//	/* Now test tuples that nearly match the session. */
//	success &= ASSERT_BOOL(false, test_address_filtering_aux(0, 0, 0, 1), "lol3");
//	success &= ASSERT_BOOL(false, test_address_filtering_aux(0, 0, 1, 0), "lol4");
//	/* The remote port is the only one that doesn't matter. */
//	success &= ASSERT_BOOL(true, test_address_filtering_aux(0, 1, 0, 0), "lol5");
//	success &= ASSERT_BOOL(false, test_address_filtering_aux(1, 0, 0, 0), "lol6");
//
//	/* Now we erase the session entry */
//	rm(session, &session_table_udp);
//	session_return(session);
//	session = NULL;
//
//	/* Repeat the "lol5" test but now the assert must be false */
//	success &= ASSERT_BOOL(false, test_address_filtering_aux(0, 1, 0, 0), "lol7");
//
//
//	return success;
//}
//
//static bool test_compare_session4(void)
//{
//	struct session_entry *s1, *s2;
//	bool success = true;
//
//	/* ------------------------------------------- */
//
//	s1 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.3", 33, "4.4.4.4", 44, L4PROTO_UDP);
//	if (!s1)
//		return false;
//	s2 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.3", 34, "4.4.4.4", 44, L4PROTO_UDP);
//	if (!s2)
//		return false;
//
//	success &= ASSERT_BOOL(true, compare_session4(s1, s2) < 0, "< 0 remote");
//	success &= ASSERT_BOOL(true, compare_session4(s2, s1) > 0, "> 0 remote");
//
//	session_return(s1);
//	session_return(s2);
//
//	/* ------------------------------------------- */
//
//	s1 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.3", 33, "4.4.4.4", 44, L4PROTO_UDP);
//	if (!s1)
//		return false;
//	s2 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.4", 33, "4.4.4.4", 44, L4PROTO_UDP);
//	if (!s2)
//		return false;
//
//	success &= ASSERT_BOOL(true, compare_session4(s1, s2) < 0, "< 0 remote");
//	success &= ASSERT_BOOL(true, compare_session4(s2, s1) > 0, "> 0 remote");
//
//	session_return(s1);
//	session_return(s2);
//
//	/* ------------------------------------------- */
//
//	s1 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.3", 33, "4.4.4.4", 44, L4PROTO_UDP);
//	if (!s1)
//		return false;
//	s2 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.3", 33, "4.4.4.4", 45, L4PROTO_UDP);
//	if (!s2)
//		return false;
//
//	success &= ASSERT_BOOL(true, compare_session4(s1, s2) < 0, "< 0 remote");
//	success &= ASSERT_BOOL(true, compare_session4(s2, s1) > 0, "> 0 remote");
//
//	session_return(s1);
//	session_return(s2);
//
//	/* ------------------------------------------- */
//
//	s1 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.3", 33, "4.4.4.4", 44, L4PROTO_UDP);
//	if (!s1)
//		return false;
//	s2 = session_create_str("1::1", 11, "2::2", 22, "3.3.3.3", 33, "4.4.4.5", 44, L4PROTO_UDP);
//	if (!s2)
//		return false;
//
//	success &= ASSERT_BOOL(true, compare_session4(s1, s2) < 0, "<< 0 remote");
//	success &= ASSERT_BOOL(true, compare_session4(s2, s1) > 0, ">> 0 remote");
//
//	session_return(s1);
//	session_return(s2);
//
//	return success;
//}

enum session_fate expire_fn(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static bool init(void)
{
	if (is_error(config_init(false)))
		goto config_fail;
//	if (is_error(pktqueue_init()))
//		goto pktqueue_fail;
//	if (is_error(pool4_init(NULL, 0)))
//		goto pool4_fail;
//	if (is_error(pool6_init(NULL, 0)))
//		goto pool6_fail;
	if (is_error(bibdb_init()))
		goto bib_fail;
	if (sessiondb_init(expire_fn, expire_fn))
		goto session_fail;

	return true;

session_fail:
	bibdb_destroy();
bib_fail:
//	pool6_destroy();
//pool6_fail:
//	pool4_destroy();
//pool4_fail:
//	pktqueue_destroy();
//pktqueue_fail:
	config_destroy();
config_fail:
	return false;
}

static void end(void)
{
	sessiondb_destroy();
//	bibdb_destroy();
//	pool6_destroy();
//	pool4_destroy();
//	pktqueue_destroy();
//	config_destroy();
}

int init_module(void)
{
	START_TESTS("Session");

	INIT_CALL_END(init(), simple_session(), end(), "Single Session");
//	INIT_CALL_END(init(), test_address_filtering(), end(), "Address-dependent filtering.");
//	INIT_CALL_END(init(), test_compare_session4(), end(), "compare_session4()");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
