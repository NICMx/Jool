#include <linux/module.h>
#include "nat64/mod/common/packet.h"

#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/skb_generator.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Packet test");

static struct in6_addr dummies6[2];
static struct in_addr dummies4[2];

/**
 * Note that the tuple being sent to skb_create_fn() lacks protocols.
 */
static struct sk_buff *create_skb4(u16 payload_len, skb_creator skb_create_fn)
{
	struct sk_buff *skb;
	struct tuple tuple4;

	tuple4.src.addr4.l3 = dummies4[0];
	tuple4.src.addr4.l4 = 5644;
	tuple4.dst.addr4.l3 = dummies4[1];
	tuple4.dst.addr4.l4 = 6721;

	return (is_error(skb_create_fn(&tuple4, &skb, payload_len, 32))) ? NULL : skb;
}

/**
 * Note that the tuple being sent to skb_create_fn() lacks protocols.
 */
static struct sk_buff *create_skb6(u16 payload_len, skb_creator skb_create_fn)
{
	struct sk_buff *skb;
	struct tuple tuple6;

	tuple6.src.addr6.l3 = dummies6[0];
	tuple6.src.addr6.l4 = 5644;
	tuple6.dst.addr6.l3 = dummies6[1];
	tuple6.dst.addr6.l4 = 6721;

	return (is_error(skb_create_fn(&tuple6, &skb, payload_len, 32))) ? NULL : skb;
}

static bool test_function_is_dont_fragment_set(void)
{
	struct iphdr hdr;
	bool success = true;

	hdr.frag_off = cpu_to_be16(0x0000);
	success &= assert_equals_u16(0, is_dont_fragment_set(&hdr), "All zeroes");

	hdr.frag_off = cpu_to_be16(0x4000);
	success &= assert_equals_u16(1, is_dont_fragment_set(&hdr), "All zeroes except DF");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	success &= assert_equals_u16(1, is_dont_fragment_set(&hdr), "All ones");

	hdr.frag_off = cpu_to_be16(0xBFFF);
	success &= assert_equals_u16(0, is_dont_fragment_set(&hdr), "All ones except DF");

	return success;
}

static bool test_function_is_more_fragments_set(void)
{
	struct iphdr hdr;
	bool success = true;

	hdr.frag_off = cpu_to_be16(0x0000);
	success &= assert_equals_u16(0, is_more_fragments_set_ipv4(&hdr), "All zeroes");

	hdr.frag_off = cpu_to_be16(0x2000);
	success &= assert_equals_u16(1, is_more_fragments_set_ipv4(&hdr), "All zeroes except MF");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	success &= assert_equals_u16(1, is_more_fragments_set_ipv4(&hdr), "All ones");

	hdr.frag_off = cpu_to_be16(0xDFFF);
	success &= assert_equals_u16(0, is_more_fragments_set_ipv4(&hdr), "All ones except MF");

	return success;
}

static bool test_function_build_ipv4_frag_off_field(void)
{
	bool success = true;

	success &= assert_equals_u16(0x400F, be16_to_cpu(build_ipv4_frag_off_field(1, 0, 120)),
			"Simple 1");
	success &= assert_equals_u16(0x202B, be16_to_cpu(build_ipv4_frag_off_field(0, 1, 344)),
			"Simple 2");

	return success;
}

static bool test_inner_packet_validation4(void)
{
	struct sk_buff *skb = NULL;
	bool result = true;

	/* Internally call the function to evaluate -> skb_init_cb_ipv4(skb) */
	skb = create_skb4(100, create_skb4_icmp_error);
	result &= assert_not_equals_ptr(NULL, skb, "validate complete inner pkt 4");
	if (skb)
		kfree_skb(skb);

	skb = create_skb4(30, create_skb4_icmp_error);
	result &= assert_equals_ptr(NULL, skb, "validate incomplete tcp inner pkt 4");
	if (skb)
		kfree_skb(skb);

	skb = create_skb4(15, create_skb4_icmp_error);
	result &= assert_equals_ptr(NULL, skb, "validate incomplete ipv4hdr inner pkt 4");
	if (skb)
		kfree_skb(skb);

	return result;
}

static bool test_inner_packet_validation6(void)
{
	struct sk_buff *skb = NULL;
	bool result = true;

	/* Internally call the function to evaluate -> skb_init_cb_ipv6(skb) */
	skb = create_skb6(100, create_skb6_icmp_error);
	result &= assert_not_equals_ptr(NULL, skb, "validate complete inner pkt 6");
	if (skb)
		kfree_skb(skb);

	skb = create_skb6(50, create_skb6_icmp_error);
	result &= assert_equals_ptr(NULL, skb, "validate incomplete tcp inner pkt 6");
	if (skb)
		kfree_skb(skb);

	skb = create_skb6(30, create_skb6_icmp_error);
	result &= assert_equals_ptr(NULL, skb, "validate incomplete ipv6hdr inner pkt 6");
	if (skb)
		kfree_skb(skb);

	return result;
}

int init_module(void)
{
	START_TESTS("Packet");
	if (str_to_addr6("1::1", &dummies6[0]) != 0)
		return -EINVAL;
	if (str_to_addr6("2::2", &dummies6[1]) != 0)
		return -EINVAL;
	if (str_to_addr4("1.1.1.1", &dummies4[0]) != 0)
		return -EINVAL;
	if (str_to_addr4("2.2.2.2", &dummies4[1]) != 0)
		return -EINVAL;

	CALL_TEST(test_function_is_dont_fragment_set(), "Dont fragment getter");
	CALL_TEST(test_function_is_more_fragments_set(), "More fragments getter");
	CALL_TEST(test_function_build_ipv4_frag_off_field(), "Generate frag offset + flags function");

	CALL_TEST(test_inner_packet_validation4(), "Inner packet IPv4 Validation");
	CALL_TEST(test_inner_packet_validation6(), "Inner packet IPv6 Validation");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
