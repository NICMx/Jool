#include <linux/module.h>
#include <linux/inet.h>

#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/compute_outgoing_tuple.h"
#include "nat64/unit/session.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava <ramiro.nava@gmail.mx>");
MODULE_AUTHOR("Alberto Leiva <aleiva@nic.mx>");
MODULE_DESCRIPTION("Outgoing module test");

static unsigned char *remote6 = "2001:db8::1";
static unsigned char *local6 = "64:ff9b::c0a8:0002";
static unsigned char *local4 = "203.0.113.1";
static unsigned char *remote4 = "192.168.0.2";

enum session_fate expire_fn(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

/**
 * Prepares the environment for the tests.
 *
 * @return whether the initialization was successful or not.
 */
static bool init(void)
{
	if (config_init(true))
		goto config_fail;

	if (sessiondb_init(expire_fn, expire_fn))
		goto session_fail;

	if (!session_inject(remote6, 1234, local6, 80,
			local4, 5678, remote4, 80,
			L4PROTO_UDP, true))
		goto full_fail;
	if (!session_inject(remote6, 1234, local6, 80,
			local4, 5678, remote4, 80,
			L4PROTO_TCP, true))
		goto full_fail;
	if (!session_inject(remote6, 1234, local6, 1234,
			local4, 80, remote4, 80,
			L4PROTO_ICMP, true))
		goto full_fail;

	return true;

full_fail:
	sessiondb_destroy();
session_fail:
	config_destroy();
config_fail:
	return false;
}

/**
 * Frees from memory the stuff we created during init().
 */
static void cleanup(void)
{
	sessiondb_destroy();
}

static bool test_6to4(l4_protocol l4_proto)
{
	struct tuple in, out;
	int field = 0;
	bool success = true;

	if (is_error(init_tuple6(&in, remote6, 1234, local6, 80, l4_proto)))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, compute_out_tuple(&in, &out, NULL), "Call");
	success &= ASSERT_INT(L3PROTO_IPV4, out.l3_proto, "l3 proto");
 	success &= ASSERT_INT(l4_proto, out.l4_proto, "l4 proto");
 	success &= ASSERT_ADDR4(local4, &out.src.addr4.l3, "src addr");
 	if (l4_proto == L4PROTO_ICMP)
 		success &= ASSERT_UINT(80, out.src.addr4.l4, "src port (icmp id)");
 	else
 		success &= ASSERT_UINT(5678, out.src.addr4.l4, "src port");
 	success &= ASSERT_ADDR4(remote4, &out.dst.addr4.l3, "dst addr");
	success &= ASSERT_UINT(80, out.dst.addr4.l4, "dst port (icmp id)");
 	success &= ASSERT_INT(0, field, "unchanged field");

	return success;
}

static bool test_4to6(l4_protocol l4_proto)
{
	struct tuple in, out;
	int field = 0;
	bool success = true;

	if (is_error(init_tuple4(&in, remote4, 80, local4, 5678, l4_proto)))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, compute_out_tuple(&in, &out, NULL), "Call");
	success &= ASSERT_INT(L3PROTO_IPV6, out.l3_proto, "l3 proto");
	success &= ASSERT_INT(l4_proto, out.l4_proto, "l4 proto");
	success &= ASSERT_ADDR6(local6, &out.src.addr6.l3, "src addr");
	if (l4_proto == L4PROTO_ICMP)
		success &= ASSERT_UINT(1234, out.src.addr6.l4, "src port (icmp id)");
	else
		success &= ASSERT_UINT(80, out.src.addr6.l4, "src port");
	success &= ASSERT_ADDR6(remote6, &out.dst.addr6.l3, "dst addr");
	success &= ASSERT_UINT(1234, out.dst.addr6.l4, "dst port");
	success &= ASSERT_INT(0, field, "unchanged field");

	return success;
}

int init_module(void)
{
	START_TESTS("Outgoing");

	if (!init())
		return -EINVAL;

	CALL_TEST(test_6to4(L4PROTO_UDP), "Tuple-5, 6 to 4, UDP");
	CALL_TEST(test_4to6(L4PROTO_UDP), "Tuple-5, 4 to 6, UDP");
	CALL_TEST(test_6to4(L4PROTO_TCP), "Tuple-5, 6 to 4, TCP");
	CALL_TEST(test_4to6(L4PROTO_TCP), "Tuple-5, 4 to 6, TCP");
	CALL_TEST(test_6to4(L4PROTO_ICMP), "Tuple-3, 6 to 4, ICMP");
	CALL_TEST(test_4to6(L4PROTO_ICMP), "Tuple-3, 4 to 6, ICMP");

	cleanup();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
