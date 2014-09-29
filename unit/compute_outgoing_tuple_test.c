#include <linux/module.h>
#include <linux/inet.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/compute_outgoing_tuple.h"
#include "nat64/unit/bib.h"
#include "nat64/unit/types.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ramiro Nava <ramiro.nava@gmail.mx>");
MODULE_AUTHOR("Alberto Leiva <aleiva@nic.mx>");
MODULE_DESCRIPTION("Outgoing module test");


static unsigned char *remote_ipv6_str = "2001:db8::1";
static unsigned char *local_ipv6_str = "64:ff9b::c0a8:0002";
static unsigned char *local_ipv4_str = "203.0.113.1";
static unsigned char *remote_ipv4_str = "192.168.0.2";


/**
 * Prepares the environment for the tests.
 *
 * @return whether the initialization was successful or not.
 */
static bool init(void)
{
	l4_protocol l4_protos[] = { L4PROTO_UDP, L4PROTO_TCP, L4PROTO_ICMP };
	int i;

	if (is_error(bibdb_init()))
		return false;

	for (i = 0; i < ARRAY_SIZE(l4_protos); i++) {
		if (!bib_inject_str(remote_ipv6_str, 1500, local_ipv4_str, 80, l4_protos[i])) {
			bibdb_destroy();
			return false;
		}
	}

	return true;
}

/**
 * Frees from memory the stuff we created during init().
 */
static void cleanup(void)
{
	bibdb_destroy();
}

static bool test_6to4(l4_protocol l4_proto)
{
	struct tuple in, out;
	bool success = true;
	int field = 0;

	/* 123 is whatever. Lookup should use the 1500. */
	if (is_error(init_ipv6_tuple(&in, remote_ipv6_str, 1500, local_ipv6_str, 123, l4_proto)))
		return false;

	success &= assert_equals_int(VER_CONTINUE, compute_out_tuple(&in, &out, &field), "Call");
	success &= assert_equals_u16(80, out.src.addr4.l4, "Source port");

	if (l4_proto != L4PROTO_ICMP)
		success &= assert_equals_u16(123, out.dst.addr4.l4, "Destination port");
	else
		success &= assert_equals_u16(80, out.dst.addr4.l4, "ICMP ID");
	success &= assert_equals_ipv4_str(local_ipv4_str, &out.src.addr4.l3, "Source address");
	success &= assert_equals_ipv4_str(remote_ipv4_str, &out.dst.addr4.l3, "Destination address");
	success &= assert_equals_u16(L3PROTO_IPV4, out.l3_proto, "Layer-3 protocol");
	success &= assert_equals_u8(l4_proto, out.l4_proto, "Layer-4 protocol");

	return success;
}

static bool test_4to6(l4_protocol l4_proto)
{
	struct tuple in, out;
	bool success = true;
	int field = 0;

	/* 123 is whatever. Lookup should use the 80. */
	if (is_error(init_ipv4_tuple(&in, remote_ipv4_str, 123, local_ipv4_str, 80, l4_proto)))
		return false;

	success &= assert_equals_int(VER_CONTINUE, compute_out_tuple(&in, &out, &field), "Call");
	success &= assert_equals_u16(1500, out.dst.addr6.l4, "Destination port");
	if (l4_proto != L4PROTO_ICMP)
		success &= assert_equals_u16(123, out.src.addr6.l4, "Source port");
	success &= assert_equals_ipv6_str(local_ipv6_str, &out.src.addr6.l3, "Source address");
	success &= assert_equals_ipv6_str(remote_ipv6_str, &out.dst.addr6.l3, "Destination address");
	success &= assert_equals_u16(L3PROTO_IPV6, out.l3_proto, "Layer-3 protocol");
	success &= assert_equals_u8(l4_proto, out.l4_proto, "Layer-4 protocol");

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
