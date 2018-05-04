#include <linux/module.h>
#include "nat64/mod/common/packet.h"

#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/skb_generator.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Packet test");

/**
 * Note that the tuple being sent to skb_create_fn() lacks protocols.
 */
static struct sk_buff *create_skb4(u16 payload_len, skb_creator skb_create_fn)
{
	struct sk_buff *skb;
	struct tuple tuple4;

	tuple4.src.addr4.l3.s_addr = cpu_to_be32(0x01010101);
	tuple4.src.addr4.l4 = 5644;
	tuple4.dst.addr4.l3.s_addr = cpu_to_be32(0x02020202);
	tuple4.dst.addr4.l4 = 6721;

	return skb_create_fn(&tuple4, &skb, payload_len, 32) ? NULL : skb;
}

/**
 * Note that the tuple being sent to skb_create_fn() lacks protocols.
 */
static struct sk_buff *create_skb6(u16 payload_len, skb_creator skb_create_fn)
{
	struct sk_buff *skb;
	struct tuple tuple6;

	tuple6.src.addr6.l3.s6_addr32[0] = cpu_to_be32(0x00010000);
	tuple6.src.addr6.l3.s6_addr32[1] = 0;
	tuple6.src.addr6.l3.s6_addr32[2] = 0;
	tuple6.src.addr6.l3.s6_addr32[3] = cpu_to_be32(0x00000001);
	tuple6.src.addr6.l4 = 5644;
	tuple6.dst.addr6.l3.s6_addr32[0] = cpu_to_be32(0x00020000);
	tuple6.dst.addr6.l3.s6_addr32[1] = 0;
	tuple6.dst.addr6.l3.s6_addr32[2] = 0;
	tuple6.dst.addr6.l3.s6_addr32[3] = cpu_to_be32(0x00000002);
	tuple6.dst.addr6.l4 = 6721;

	return skb_create_fn(&tuple6, &skb, payload_len, 32) ? NULL : skb;
}

static bool test_function_is_df_set(void)
{
	struct iphdr hdr;
	bool success = true;

	hdr.frag_off = cpu_to_be16(0x0000);
	success &= ASSERT_UINT(0, is_df_set(&hdr), "All zeroes");

	hdr.frag_off = cpu_to_be16(0x4000);
	success &= ASSERT_UINT(IP_DF, is_df_set(&hdr), "All zeroes except DF");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	success &= ASSERT_UINT(IP_DF, is_df_set(&hdr), "All ones");

	hdr.frag_off = cpu_to_be16(0xBFFF);
	success &= ASSERT_UINT(0, is_df_set(&hdr), "All ones except DF");

	return success;
}

static bool test_function_is_mf_set(void)
{
	struct iphdr hdr;
	bool success = true;

	hdr.frag_off = cpu_to_be16(0x0000);
	success &= ASSERT_UINT(0, is_mf_set_ipv4(&hdr), "All zeroes");

	hdr.frag_off = cpu_to_be16(0x2000);
	success &= ASSERT_UINT(IP_MF, is_mf_set_ipv4(&hdr), "All zeroes except MF");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	success &= ASSERT_UINT(IP_MF, is_mf_set_ipv4(&hdr), "All ones");

	hdr.frag_off = cpu_to_be16(0xDFFF);
	success &= ASSERT_UINT(0, is_mf_set_ipv4(&hdr), "All ones except MF");

	return success;
}

static bool test_function_build_ipv4_frag_off_field(void)
{
	bool success = true;

	success &= ASSERT_BE16(0x400F, build_ipv4_frag_off_field(1, 0, 120), "Simple 1");
	success &= ASSERT_BE16(0x202B, build_ipv4_frag_off_field(0, 1, 344), "Simple 2");

	return success;
}

static bool test_inner_validation4(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	bool result = true;

	skb = create_skb4(100, create_skb4_icmp_error);
	if (!skb)
		return false;
	result &= ASSERT_INT(0, pkt_init_ipv4(&pkt, skb), "complete inner pkt");
	kfree_skb(skb);

	skb = create_skb4(30, create_skb4_icmp_error);
	if (!skb)
		return false;
	result &= ASSERT_INT(-EINVAL, pkt_init_ipv4(&pkt, skb), "incomplete inner tcp");
	kfree_skb(skb);

	skb = create_skb4(15, create_skb4_icmp_error);
	if (!skb)
		return false;
	result &= ASSERT_INT(-EINVAL, pkt_init_ipv4(&pkt, skb), "incomplete inner ipv4");
	kfree_skb(skb);

	return result;
}

static bool test_inner_validation6(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	bool result = true;

	skb = create_skb6(100, create_skb6_icmp_error);
	if (!skb)
		return false;
	result &= ASSERT_INT(0, pkt_init_ipv6(&pkt, skb), "complete inner pkt 6");
	kfree_skb(skb);

	skb = create_skb6(50, create_skb6_icmp_error); /* 40 + 8 + 40 + 20 */
	if (!skb)
		return false;
	result &= ASSERT_INT(-EINVAL, pkt_init_ipv6(&pkt, skb), "incomplete inner tcp");
	kfree_skb(skb);

	skb = create_skb6(30, create_skb6_icmp_error);
	if (!skb)
		return false;
	result &= ASSERT_INT(-EINVAL, pkt_init_ipv6(&pkt, skb), "incomplete inner ipv6hdr");
	kfree_skb(skb);

	return result;
}

int init_module(void)
{
	struct test_group test = {
		.name = "Packet",
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, test_function_is_df_set, "DF getter");
	test_group_test(&test, test_function_is_mf_set, "MF getter");
	test_group_test(&test, test_function_build_ipv4_frag_off_field, "Generate frag offset + flags function");

	test_group_test(&test, test_inner_validation4, "Inner IPv4 pkt validation");
	test_group_test(&test, test_inner_validation6, "Inner IPv6 pkt validation");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
