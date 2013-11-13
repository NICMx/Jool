#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/validator.h"
#include "nat64/unit/types.h"
#include "nat64/comm/str_utils.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

#define GENERATE_FOR_EACH true
#include "determine_incoming_tuple.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Determine Incoming Tuple Test");


static bool test_determine_in_tuple_ipv4(void)
{
	struct packet *pkt = NULL;
	struct tuple actual, expected;
	struct ipv4_pair pair4;
	bool success = true;
	int error;

	error = init_ipv4_tuple(&expected, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_UDP);
	if (error)
		return false;
	error = init_pair4(&pair4,  "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = create_packet_ipv4_udp_fragmented_disordered(&pair4, &pkt);
	if (error)
		return false;

	success &= assert_equals_int(VER_CONTINUE, determine_in_tuple(pkt, &actual), "verdict");
	success &= assert_equals_tuple(&expected, &actual, "tuple");

	pkt_kfree(pkt, true);
	return success;
}

static bool test_determine_in_tuple_ipv6(void)
{
	struct packet *pkt = NULL;
	struct tuple actual, expected;
	struct ipv6_pair pair6;
	bool success = true;
	int error;

	error = init_ipv6_tuple(&expected, "1::2", 1212, "3::4", 3434, L4PROTO_TCP);
	if (error)
		return false;
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = create_packet_ipv6_tcp_fragmented_disordered(&pair6, &pkt);
	if (error)
		return false;

	success &= assert_equals_int(VER_CONTINUE, determine_in_tuple(pkt, &actual), "verdict");
	success &= assert_equals_tuple(&expected, &actual, "tuple");

	pkt_kfree(pkt, true);
	return success;
}

int init_module(void)
{
	START_TESTS("Determine incoming tuple");

	CALL_TEST(test_determine_in_tuple_ipv4(), "Determine incoming tuple of a 3 fragments IPv4 packet.");
	CALL_TEST(test_determine_in_tuple_ipv6(), "Determine incoming tuple of a 3 fragments IPv6 packet.");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
