#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/validator.h"
#include "nat64/unit/types.h"
#include "nat64/common/str_utils.h"
#include "nat64/common/constants.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"

#define GENERATE_FOR_EACH true
#include "determine_incoming_tuple.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Determine Incoming Tuple Test");


static bool test_determine_in_tuple_ipv4(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	struct tuple actual, expected;
	bool success = true;

	if (is_error(init_ipv4_tuple(&expected, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb4_udp(&expected, &skb, 8, 32)))
		return false;
	if (is_error(pkt_init_ipv4(&pkt, skb)))
		return false;

	success &= assert_equals_int(VERDICT_CONTINUE, determine_in_tuple(&pkt, &actual), "verdict");
	success &= assert_equals_tuple(&expected, &actual, "tuple");

	kfree_skb(skb);
	return success;
}

static bool test_determine_in_tuple_ipv6(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	struct tuple actual, expected;
	bool success = true;

	if (is_error(init_ipv6_tuple(&expected, "1::2", 1212, "3::4", 3434, L4PROTO_TCP)))
		return false;
	if (is_error(create_skb6_tcp(&expected, &skb, 8, 32)))
		return false;
	if (is_error(pkt_init_ipv6(&pkt, skb)))
		return false;

	success &= assert_equals_int(VERDICT_CONTINUE, determine_in_tuple(&pkt, &actual), "verdict");
	success &= assert_equals_tuple(&expected, &actual, "tuple");

	kfree_skb(skb);
	return success;
}

int init_module(void)
{
	START_TESTS("Determine incoming tuple");

	CALL_TEST(test_determine_in_tuple_ipv4(), "3 fragments IPv4 packet.");
	CALL_TEST(test_determine_in_tuple_ipv6(), "3 fragments IPv6 packet.");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
