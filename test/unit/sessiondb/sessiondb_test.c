#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/session.h"
#include "nat64/unit/unit_test.h"
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("Session DB module test.");

static struct bib *db;
static const l4_protocol PROTO = L4PROTO_UDP;
static struct session_entry session_instances[16];
static struct session_entry *sessions[4][4][4][4];

static void init_src6(struct ipv6_transport_addr *addr, __u16 last_byte,
		__u16 port)
{
	addr->l3.s6_addr32[0] = cpu_to_be32(0x20010db8u);
	addr->l3.s6_addr32[1] = 0;
	addr->l3.s6_addr32[2] = 0;
	addr->l3.s6_addr32[3] = cpu_to_be32(last_byte);
	addr->l4 = port;
}

static void init_dst6(struct ipv6_transport_addr *addr, __u16 last_byte,
		__u16 port)
{
	addr->l3.s6_addr32[0] = cpu_to_be32(0x0064ff9bu);
	addr->l3.s6_addr32[1] = 0;
	addr->l3.s6_addr32[2] = 0;
	addr->l3.s6_addr32[3] = cpu_to_be32(0xc0000200u | last_byte);
	addr->l4 = port;
}

static void init_src4(struct ipv4_transport_addr *addr, __u16 last_byte,
		__u16 port)
{
	addr->l3.s_addr = cpu_to_be32(0xcb007100u | last_byte);
	addr->l4 = port;
}

static void init_dst4(struct ipv4_transport_addr *addr, __u16 last_byte,
		__u16 port)
{
	addr->l3.s_addr = cpu_to_be32(0xc0000200u | last_byte);
	addr->l4 = port;
}

static int compare_session_foreach_cb(struct session_entry *session, void *arg)
{
	return session_equals(session, arg);
}

static bool session_exists(struct session_entry *session)
{
	struct session_foreach_func func = {
			.cb = compare_session_foreach_cb,
			.arg = session,
	};

	/* This is the closest we currently have to a find_session function. */
	return bib_foreach_session(db, session->proto, &func, NULL);
}

static bool assert_session(unsigned int la, unsigned int lp,
		unsigned int ra, unsigned int rp)
{
	struct session_entry session;
	int expected;

	init_src6(&session.src6, la, lp);
	init_dst6(&session.dst6, ra, rp);
	init_src4(&session.src4, la, lp);
	init_dst4(&session.dst4, ra, rp);
	session.proto = PROTO;

	expected = !!sessions[la][lp][ra][rp];
	return ASSERT_INT(expected, session_exists(db, &session),
			"session %u %u %u %u lookup", la, lp, ra, rp);
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
					success &= assert_session(la, lp, ra, rp);
				}
			}
		}
	}

	return success;
}

static bool inject(unsigned int index, __u32 src_addr, __u16 src_id,
		__u32 dst_addr, __u16 dst_id)
{
	struct session_entry *entry;
	int error;

	entry = &session_instances[index];
	sessions[src_addr][src_id][dst_addr][dst_id] = entry;

	init_src6(&entry->src6, src_addr, src_id);
	init_dst6(&entry->dst6, dst_addr, dst_id);
	init_src4(&entry->src4, src_addr, src_id);
	init_dst4(&entry->dst4, dst_addr, dst_id);
	entry->proto = L4PROTO_UDP;
	entry->state = ESTABLISHED;
	entry->established = true;
	entry->update_time = jiffies;
	entry->timeout = UDP_DEFAULT;

	error = bib_add_session(db, entry, NULL);
	if (error) {
		log_err("Errcode %d on sessiontable_add.", error);
		return false;
	}

	return true;
}

static bool insert_test_sessions(void)
{
	bool success = true;

	memset(session_instances, 0, sizeof(session_instances));
	memset(sessions, 0, sizeof(sessions));

	success &= inject(0, 1, 2, 2, 2);
	success &= inject(1, 1, 1, 2, 1);
	success &= inject(2, 2, 1, 2, 1);
	success &= inject(3, 2, 2, 2, 2);
	success &= inject(4, 1, 1, 2, 2);
	success &= inject(5, 2, 2, 1, 1);
	success &= inject(6, 2, 1, 1, 1);
	success &= inject(7, 1, 1, 1, 1);
	success &= inject(8, 2, 2, 1, 2);
	success &= inject(9, 1, 2, 1, 1);
	success &= inject(10, 2, 1, 1, 2);
	success &= inject(11, 1, 2, 1, 2);
	success &= inject(12, 2, 1, 2, 2);
	success &= inject(13, 1, 1, 1, 2);
	success &= inject(14, 1, 2, 2, 1);
	success &= inject(15, 2, 2, 2, 1);

	return success ? test_db() : false;
}

static bool flush(void)
{
	log_debug("Flushing.");
	bib_flush(db);

	memset(session_instances, 0, sizeof(session_instances));
	memset(sessions, 0, sizeof(sessions));
	return test_db();
}

static bool simple_session(void)
{
	struct ipv4_range range;
	bool success = true;

	if (!insert_test_sessions())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Deleting sessions by BIB.");
	range.prefix.address.s_addr = cpu_to_be32(0xcb007101u);
	range.prefix.len = 32;
	range.ports.min = 1;
	range.ports.max = 1;
	bib_rm_range(db, PROTO, &range);

	sessions[1][1][2][2] = NULL;
	sessions[1][1][2][1] = NULL;
	sessions[1][1][1][1] = NULL;
	sessions[1][1][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	log_debug("Deleting again.");
	bib_rm_range(db, PROTO, &range);
	success &= test_db();

	/* ---------------------------------------------------------- */

	success &= flush();
	if (!insert_test_sessions())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Deleting by range (all addresses, lower ports).");
	range.prefix.address.s_addr = cpu_to_be32(0xcb007100u);
	range.prefix.len = 30;
	range.ports.min = 0;
	range.ports.max = 1;
	bib_rm_range(db, PROTO, &range);

	sessions[2][1][2][1] = NULL;
	sessions[2][1][1][1] = NULL;
	sessions[1][1][2][2] = NULL;
	sessions[2][1][2][2] = NULL;
	sessions[2][1][1][2] = NULL;
	sessions[1][1][2][1] = NULL;
	sessions[1][1][1][1] = NULL;
	sessions[1][1][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	success &= flush();
	if (!insert_test_sessions())
		return false;

	/* ---------------------------------------------------------- */

	log_debug("Deleting by range (lower addresses, all ports).");
	range.prefix.address.s_addr = cpu_to_be32(0xcb007100u);
	range.prefix.len = 31;
	range.ports.min = 0;
	range.ports.max = 65535;
	bib_rm_range(db, PROTO, &range);

	sessions[1][2][2][2] = NULL;
	sessions[1][1][2][2] = NULL;
	sessions[1][2][1][1] = NULL;
	sessions[1][1][2][1] = NULL;
	sessions[1][2][2][1] = NULL;
	sessions[1][2][1][2] = NULL;
	sessions[1][1][1][1] = NULL;
	sessions[1][1][1][2] = NULL;
	success &= test_db();

	/* ---------------------------------------------------------- */

	success &= flush();
	return success;
}

//static bool test_allow_aux(__u32 local_addr, __u16 local_port,
//		__u32 remote_addr, __u16 remote_port)
//{
//	struct tuple tuple4;
//
//	tuple4.src.addr4.l3.s_addr = cpu_to_be32(remote_addr);
//	tuple4.src.addr4.l4 = remote_port;
//	tuple4.dst.addr4.l3.s_addr = cpu_to_be32(local_addr);
//	tuple4.dst.addr4.l4 = local_port;
//	tuple4.l4_proto = L4PROTO_UDP;
//	tuple4.l3_proto = L3PROTO_IPV4;
//
//	log_tuple(&tuple4);
//	return sessiondb_allow(db, &tuple4);
//}
//
//static bool test_allow(void)
//{
//	struct session_entry *session;
//	bool success = true;
//
//	/* Init. */
//	session = session_inject(db, "2001:db8::2", 20, "64::6", 60,
//			"192.0.2.1", 10, "203.0.113.2", 20, L4PROTO_UDP, true);
//	if (!session)
//		return false;
//
//	/* Test admittance when the tuple and session match perfectly. */
//	success &= ASSERT_BOOL(true,
//			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 20),
//			"perfect match");
//	/* Test a tuple that completely mismatches the session. */
//	success &= ASSERT_BOOL(false,
//			test_allow_aux(0x12345678u, 90, 0x90876543u, 21),
//			"perfect mismatch");
//	/*
//	 * Now test tuples that nearly match the session.
//	 * (The remote port is the only one that doesn't matter.)
//	 */
//	success &= ASSERT_BOOL(true,
//			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 21),
//			"src port mismatch");
//	success &= ASSERT_BOOL(false,
//			test_allow_aux(0xc0000201u, 10, 0x90876543u, 20),
//			"src addr mismatch");
//	success &= ASSERT_BOOL(false,
//			test_allow_aux(0xc0000201u, 90, 0xcb007102u, 20),
//			"dst port mismatch");
//	success &= ASSERT_BOOL(false,
//			test_allow_aux(0x12345678u, 10, 0xcb007102u, 20),
//			"dst addr mismatch");
//
//	sessiondb_flush(db);
//	session_put(session, true);
//	session = NULL;
//
//	/*
//	 * Now that the original session is no longer in the DB, the previously
//	 * positive tests should now fail.
//	 */
//	success &= ASSERT_BOOL(false,
//			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 20),
//			"perfect match deleted");
//	success &= ASSERT_BOOL(false,
//			test_allow_aux(0xc0000201u, 10, 0xcb007102u, 21),
//			"src port mismatch deleted");
//
//	return success;
//}

enum session_fate tcp_expired_cb(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static bool init(void)
{
	if (bib_init())
		return false;
	db = bib_create();
	if (!db)
		bib_destroy();
	return db;
}

static void end(void)
{
	bib_put(db);
	bib_destroy();
}

int init_module(void)
{
	START_TESTS("Session");

	INIT_CALL_END(init(), simple_session(), end(), "Single Session");
//	INIT_CALL_END(init(), test_allow(), end(), "Allow function");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
