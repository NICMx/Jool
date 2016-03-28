#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/session.h"
#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "session/db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("Session DB module test.");

struct sessiondb *db;
static const l4_protocol PROTO = L4PROTO_UDP;
struct session_entry *sessions[16];
static struct session_entry *sessions4[4][4][4][4];
static struct session_entry *sessions6[4][4][4][4];

static bool assert4(unsigned int la, unsigned int lp,
		unsigned int ra, unsigned int rp)
{
	struct session_entry *session = NULL;
	struct tuple tuple4;
	bool success = true;

	tuple4.src.addr4.l3.s_addr = cpu_to_be32(0xcb007100u | ra);
	tuple4.src.addr4.l4 = rp;
	tuple4.dst.addr4.l3.s_addr = cpu_to_be32(0xc0000200u | la);
	tuple4.dst.addr4.l4 = lp;
	tuple4.l3_proto = L3PROTO_IPV4;
	tuple4.l4_proto = PROTO;

	if (sessions4[la][lp][ra][rp]) {
		success &= ASSERT_INT(0,
				sessiondb_find(db, &tuple4, NULL, NULL, &session),
				"get4 code - %u %u %u %u", la, lp, ra, rp);
		success &= ASSERT_SESSION(sessions4[la][lp][ra][rp], session,
				"get4 session");
	} else {
		success &= ASSERT_INT(-ESRCH,
				sessiondb_find(db, &tuple4, NULL, NULL, &session),
				"get4 code - %u %u %u %u", la, lp, ra, rp);
	}

	if (session)
		session_put(session, false);

	return success;
}

static bool assert6(unsigned int la, unsigned int lp,
		unsigned int ra, unsigned int rp)
{
	struct session_entry *session = NULL;
	struct tuple tuple6;
	bool success = true;

	tuple6.src.addr6.l3.s6_addr32[0] = cpu_to_be32(0x20010db8u);
	tuple6.src.addr6.l3.s6_addr32[1] = 0;
	tuple6.src.addr6.l3.s6_addr32[2] = 0;
	tuple6.src.addr6.l3.s6_addr32[3] = cpu_to_be32(ra);
	tuple6.src.addr6.l4 = rp;
	tuple6.dst.addr6.l3.s6_addr32[0] = cpu_to_be32(0x00640000u);
	tuple6.dst.addr6.l3.s6_addr32[1] = 0;
	tuple6.dst.addr6.l3.s6_addr32[2] = 0;
	tuple6.dst.addr6.l3.s6_addr32[3] = cpu_to_be32(la);
	tuple6.dst.addr6.l4 = lp;
	tuple6.l3_proto = L3PROTO_IPV6;
	tuple6.l4_proto = PROTO;

	if (sessions6[ra][rp][la][lp]) {
		success &= ASSERT_INT(0,
				sessiondb_find(db, &tuple6, NULL, NULL, &session),
				"get6 code - %u %u %u %u", ra, rp, la, lp);
		success &= ASSERT_SESSION(sessions6[ra][rp][la][lp], session,
				"get6 session");
	} else {
		success &= ASSERT_INT(-ESRCH,
				sessiondb_find(db, &tuple6, NULL, NULL, &session),
				"get6 code - %u %u %u %u", ra, rp, la, lp);
	}

	if (session)
		session_put(session, false);

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
	unsigned int i;

	memset(sessions4, 0, sizeof(sessions4));
	memset(sessions6, 0, sizeof(sessions6));

	sessions[ 0] = session_inject(db, "2001:db8::1", 2, "64::2", 2, "192.0.2.2", 1, "203.0.113.2", 1, PROTO, true);
	sessions[ 1] = session_inject(db, "2001:db8::1", 1, "64::2", 1, "192.0.2.2", 2, "203.0.113.2", 2, PROTO, true);
	sessions[ 2] = session_inject(db, "2001:db8::2", 1, "64::2", 1, "192.0.2.2", 2, "203.0.113.1", 2, PROTO, true);
	sessions[ 3] = session_inject(db, "2001:db8::2", 2, "64::2", 2, "192.0.2.2", 2, "203.0.113.1", 1, PROTO, true);
	sessions[ 4] = session_inject(db, "2001:db8::1", 1, "64::2", 2, "192.0.2.1", 2, "203.0.113.2", 2, PROTO, true);
	sessions[ 5] = session_inject(db, "2001:db8::2", 2, "64::1", 1, "192.0.2.2", 1, "203.0.113.1", 1, PROTO, true);
	sessions[ 6] = session_inject(db, "2001:db8::2", 1, "64::1", 1, "192.0.2.1", 1, "203.0.113.2", 2, PROTO, true);
	sessions[ 7] = session_inject(db, "2001:db8::1", 1, "64::1", 1, "192.0.2.2", 1, "203.0.113.2", 2, PROTO, true);
	sessions[ 8] = session_inject(db, "2001:db8::2", 2, "64::1", 2, "192.0.2.1", 2, "203.0.113.1", 1, PROTO, true);
	sessions[ 9] = session_inject(db, "2001:db8::1", 2, "64::1", 1, "192.0.2.2", 2, "203.0.113.2", 1, PROTO, true);
	sessions[10] = session_inject(db, "2001:db8::2", 1, "64::1", 2, "192.0.2.2", 1, "203.0.113.1", 2, PROTO, true);
	sessions[11] = session_inject(db, "2001:db8::1", 2, "64::1", 2, "192.0.2.1", 1, "203.0.113.2", 1, PROTO, true);
	sessions[12] = session_inject(db, "2001:db8::2", 1, "64::2", 2, "192.0.2.1", 2, "203.0.113.2", 1, PROTO, true);
	sessions[13] = session_inject(db, "2001:db8::1", 1, "64::1", 2, "192.0.2.1", 2, "203.0.113.1", 2, PROTO, true);
	sessions[14] = session_inject(db, "2001:db8::1", 2, "64::2", 1, "192.0.2.1", 1, "203.0.113.1", 1, PROTO, true);
	sessions[15] = session_inject(db, "2001:db8::2", 2, "64::2", 1, "192.0.2.1", 1, "203.0.113.1", 2, PROTO, true);
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

static bool flush(void)
{
	unsigned int i;

	log_debug("Flushing.");
	sessiondb_flush(db);

	for (i = 0; i < ARRAY_SIZE(sessions); i++)
		session_put(sessions[i], true);
	memset(sessions, 0, sizeof(sessions));
	memset(sessions4, 0, sizeof(sessions4));
	memset(sessions6, 0, sizeof(sessions6));
	return test_db();
}

static bool simple_session(void)
{
	struct bib_entry bib = {
			.ipv4.l3.s_addr = cpu_to_be32(0xc0000201u),
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
	error = sessiondb_delete_by_bib(db, &bib);
	success &= ASSERT_INT(0, error, "BIB delete result");

	sessions6[2][1][1][1] = sessions4[1][1][2][2] = NULL;
	sessions6[1][2][1][2] = sessions4[1][1][2][1] = NULL;
	sessions6[1][2][2][1] = sessions4[1][1][1][1] = NULL;
	sessions6[2][2][2][1] = sessions4[1][1][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Deleting again.");
	error = sessiondb_delete_by_bib(db, &bib);
	success &= ASSERT_INT(0, error, "BIB delete result");
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Deleting by prefix6.");
	prefix6.address.s6_addr32[0] = cpu_to_be32(0x00640000u);
	prefix6.address.s6_addr32[1] = 0;
	prefix6.address.s6_addr32[2] = 0;
	prefix6.address.s6_addr32[3] = cpu_to_be32(1);
	prefix6.len = 128;
	sessiondb_rm_taddr6s(db, &prefix6);

	sessions6[2][2][1][1] = sessions4[2][1][1][1] = NULL;
	sessions6[1][1][1][1] = sessions4[2][1][2][2] = NULL;
	sessions6[2][2][1][2] = sessions4[1][2][1][1] = NULL;
	sessions6[1][2][1][1] = sessions4[2][2][2][1] = NULL;
	sessions6[2][1][1][2] = sessions4[2][1][1][2] = NULL;
	sessions6[1][1][1][2] = sessions4[1][2][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	success &= flush();
	if (!insert_test_sessions())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Deleting by taddr4s (all addresses, lower ports).");
	prefix4.address.s_addr = cpu_to_be32(0xc0000200u);
	prefix4.len = 30;
	ports.min = 0;
	ports.max = 1;
	sessiondb_rm_taddr4s(db, &prefix4, &ports);

	sessions6[1][2][2][2] = sessions4[2][1][2][1] = NULL;
	sessions6[2][2][1][1] = sessions4[2][1][1][1] = NULL;
	sessions6[2][1][1][1] = sessions4[1][1][2][2] = NULL;
	sessions6[1][1][1][1] = sessions4[2][1][2][2] = NULL;
	sessions6[2][1][1][2] = sessions4[2][1][1][2] = NULL;
	sessions6[1][2][1][2] = sessions4[1][1][2][1] = NULL;
	sessions6[1][2][2][1] = sessions4[1][1][1][1] = NULL;
	sessions6[2][2][2][1] = sessions4[1][1][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	success &= flush();
	if (!insert_test_sessions())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Deleting by taddr4s (lower addresses, all ports).");
	prefix4.address.s_addr = cpu_to_be32(0xc0000200u);
	prefix4.len = 31;
	ports.min = 0;
	ports.max = 65535;
	sessiondb_rm_taddr4s(db, &prefix4, &ports);

	sessions6[1][1][2][2] = sessions4[1][2][2][2] = NULL;
	sessions6[2][1][1][1] = sessions4[1][1][2][2] = NULL;
	sessions6[2][2][1][2] = sessions4[1][2][1][1] = NULL;
	sessions6[1][2][1][2] = sessions4[1][1][2][1] = NULL;
	sessions6[2][1][2][2] = sessions4[1][2][2][1] = NULL;
	sessions6[1][1][1][2] = sessions4[1][2][1][2] = NULL;
	sessions6[1][2][2][1] = sessions4[1][1][1][1] = NULL;
	sessions6[2][2][2][1] = sessions4[1][1][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	success &= flush();
	return success;
}

static bool test_allow_aux(__u32 local_addr, __u16 local_port,
		__u32 remote_addr, __u16 remote_port)
{
	struct tuple tuple4;

	tuple4.src.addr4.l3.s_addr = cpu_to_be32(remote_addr);
	tuple4.src.addr4.l4 = remote_port;
	tuple4.dst.addr4.l3.s_addr = cpu_to_be32(local_addr);
	tuple4.dst.addr4.l4 = local_port;
	tuple4.l4_proto = L4PROTO_UDP;
	tuple4.l3_proto = L3PROTO_IPV4;

	log_tuple(&tuple4);
	return sessiondb_allow(db, &tuple4);
}

static bool test_allow(void)
{
	struct session_entry *session;
	bool success = true;

	/* Init. */
	session = session_inject(db, "2001:db8::2", 20, "64::6", 60,
			"192.0.2.1", 10, "203.0.113.2", 20, L4PROTO_UDP, true);
	if (!session)
		return false;

	/* Test admittance when the tuple and session match perfectly. */
	success &= ASSERT_BOOL(true,
			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 20),
			"perfect match");
	/* Test a tuple that completely mismatches the session. */
	success &= ASSERT_BOOL(false,
			test_allow_aux(0x12345678u, 90, 0x90876543u, 21),
			"perfect mismatch");
	/*
	 * Now test tuples that nearly match the session.
	 * (The remote port is the only one that doesn't matter.)
	 */
	success &= ASSERT_BOOL(true,
			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 21),
			"src port mismatch");
	success &= ASSERT_BOOL(false,
			test_allow_aux(0xc0000201u, 10, 0x90876543u, 20),
			"src addr mismatch");
	success &= ASSERT_BOOL(false,
			test_allow_aux(0xc0000201u, 90, 0xcb007102u, 20),
			"dst port mismatch");
	success &= ASSERT_BOOL(false,
			test_allow_aux(0x12345678u, 10, 0xcb007102u, 20),
			"dst addr mismatch");

	sessiondb_flush(db);
	session_put(session, true);
	session = NULL;

	/*
	 * Now that the original session is no longer in the DB, the previously
	 * positive tests should now fail.
	 */
	success &= ASSERT_BOOL(false,
			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 20),
			"perfect match deleted");
	success &= ASSERT_BOOL(false,
			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 21),
			"src port mismatch deleted");

	return success;
}

enum session_fate tcp_expired_cb(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static bool init(void)
{
	if (session_init())
		return false;
	if (sessiondb_init(&db)) {
		session_destroy();
		return false;
	}

	return true;
}

static void end(void)
{
	sessiondb_put(db);
	session_destroy();
}

int init_module(void)
{
	START_TESTS("Session");

	INIT_CALL_END(init(), simple_session(), end(), "Single Session");
	INIT_CALL_END(init(), test_allow(), end(), "Allow function");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
