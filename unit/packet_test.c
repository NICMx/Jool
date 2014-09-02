#include <linux/module.h>
#include "nat64/mod/packet.h"

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/skb_generator.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Packet test");

static struct in6_addr dummies6[2];
static struct in_addr dummies4[2];

static struct sk_buff *create_skb4(u16 payload_len,
		int (*skb_create_fn)(struct ipv4_pair *, struct sk_buff **, u16))
{
	struct sk_buff *skb;
	struct ipv4_pair pair4;

	pair4.remote.address = dummies4[0];
	pair4.remote.l4_id = 5644;
	pair4.local.address = dummies4[1];
	pair4.local.l4_id = 6721;

	return (is_error(skb_create_fn(&pair4, &skb, payload_len))) ? NULL : skb;
}

static struct sk_buff *create_skb6(u16 payload_len,
		int (*skb_create_fn)(struct ipv6_pair *, struct sk_buff **, u16))
{
	struct sk_buff *skb;
	struct ipv6_pair pair6;

	pair6.remote.address = dummies6[0];
	pair6.remote.l4_id = 5644;
	pair6.local.address = dummies6[1];
	pair6.local.l4_id = 6721;

	return (is_error(skb_create_fn(&pair6, &skb, payload_len))) ? NULL : skb;
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

/**
 * Asserts the database never leaves UDP checksums uncomputed.
 * IPv4-to-IPv6 direction.
 */
static bool test_udp_checksum_4(void)
{
	struct sk_buff *skb1, *skb2;
	struct ipv4_pair pair4;
	bool success = true;

	if (init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678) != 0)
		return false;
	if (create_skb_ipv4_udp(&pair4, &skb1, 8) != 0)
		return false;

	udp_hdr(skb1)->check = cpu_to_be16(0x1234);
	success &= assert_equals_int(0, fix_checksums_ipv4(skb1), "Function result 1");
	/* Non-zero IPv4 checksums should not be mangled even if they're wrong. */
	success &= assert_equals_csum(cpu_to_be16(0x1234), udp_hdr(skb1)->check, "Same IPv4 csum");

	udp_hdr(skb1)->check = cpu_to_be16(0);
	success &= assert_equals_int(0, fix_checksums_ipv4(skb1), "Function result 2");
	/* Zero-checksums should be computed. */
	/* BTW: Checksum verified in Wireshark. */
	success &= assert_equals_csum(cpu_to_be16(0xa139), udp_hdr(skb1)->check, "Computed IPv4 csum");

	kfree_skb(skb1);

	if (create_skb_ipv4_udp_frag(&pair4, &skb1, 8, 24, true, true, 0) != 0)
		return false;
	if (create_skb_ipv4_udp_frag(&pair4, &skb2, 8, 24, true, false, 16) != 0)
		return false;

	skb1->next = skb2;
	skb2->prev = skb1;

	udp_hdr(skb1)->check = cpu_to_be16(0);
	success &= assert_equals_int(0, fix_checksums_ipv4(skb1), "Function result 3");
	/* The checksum should consider all fragments. */
	/* BTW: Checksum verified in Wireshark. */
	success &= assert_equals_csum(cpu_to_be16(0x9519), udp_hdr(skb1)->check, "Frag IPv4 csum");

	kfree_skb_queued(skb1);

	return success;
}

/**
 * Simply asserts the database doesn't mangle IPv6-UDP checksums.
 * IPv6-to-IPv4 direction.
 */
static bool test_udp_checksum_6(void)
{
	struct sk_buff *skb;
	struct ipv6_pair pair6;
	bool success = true;

	if (init_pair6(&pair6, "8::5", 8765, "5::8", 5678) != 0)
		return false;
	if (create_skb_ipv6_udp(&pair6, &skb, 8) != 0)
		return false;

	udp_hdr(skb)->check = cpu_to_be16(0x1234);
	success &= assert_equals_int(0, fix_checksums_ipv6(skb), "Function result 1");
	/* IPv6 checksums should not be mangled even if they're wrong. */
	success &= assert_equals_csum(cpu_to_be16(0x1234), udp_hdr(skb)->check, "Computed IPv6 csum1");

	udp_hdr(skb)->check = cpu_to_be16(0);
	success &= assert_equals_int(0, fix_checksums_ipv6(skb), "Function result 2");
	/* IPv6 checksums should not be mangled even if they're wrong. */
	success &= assert_equals_csum(cpu_to_be16(0), udp_hdr(skb)->check, "Computed IPv6 csum2");

	return success;
}

static bool test_validate_icmp_integrity(void)
{
	struct sk_buff *skb_icmp4_info, *skb_icmp6_info;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct hdr_iterator iterator6;
	bool success = true;
	int error;

	if (init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678) != 0)
		return false;
	if (init_pair6(&pair6, "8::5", 8765, "5::8", 5678) != 0)
		return false;

	if (create_skb_ipv4_icmp_info(&pair4, &skb_icmp4_info, 50) != 0)
		return false;

	if (create_skb_ipv6_icmp_info(&pair6, &skb_icmp6_info, 50) != 0) {
		kfree(skb_icmp4_info);
	}

	error = validate_ipv4_integrity(ip_hdr(skb_icmp4_info), skb_icmp4_info->len, false);
	success &= assert_equals_int(0, error, "validate ipv4_integrity");
	error = fix_checksums_ipv4(skb_icmp4_info);
	success &= assert_equals_int(0, error, "validate fix_checksums_ipv4_icmp");
	error = validate_ipv6_integrity(ipv6_hdr(skb_icmp6_info), skb_icmp6_info->len, false, &iterator6);
	success &= assert_equals_int(0, error, "Validate ipv6 integrity");
	error = fix_checksums_ipv6(skb_icmp6_info);
	success &= assert_equals_int(0, error, "validate fix_checksums_ipv6_icmp");

	kfree(skb_icmp4_info);
	kfree(skb_icmp6_info);

	return success;
}

static bool test_inner_packet_validation4(void)
{
	struct sk_buff *skb = NULL;
	bool result = true;

	/* Internally call the function to evaluate -> skb_init_cb_ipv4(skb) */
	skb = create_skb4(100, create_skb_ipv4_icmp_error);
	result &= assert_not_equals_ptr(NULL, skb, "validate complete inner pkt 4");
	if (skb)
		kfree_skb(skb);

	skb = create_skb4(30, create_skb_ipv4_icmp_error);
	result &= assert_equals_ptr(NULL, skb, "validate incomplete tcp inner pkt 4");
	if (skb)
		kfree_skb(skb);

	skb = create_skb4(15, create_skb_ipv4_icmp_error);
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
	skb = create_skb6(100, create_skb_ipv6_icmp_error);
	result &= assert_not_equals_ptr(NULL, skb, "validate complete inner pkt 6");
	if (skb)
		kfree_skb(skb);

	skb = create_skb6(50, create_skb_ipv6_icmp_error);
	result &= assert_equals_ptr(NULL, skb, "validate incomplete tcp inner pkt 6");
	if (skb)
		kfree_skb(skb);

	skb = create_skb6(30, create_skb_ipv6_icmp_error);
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

	CALL_TEST(test_udp_checksum_4(), "UDP-checksum 4");
	CALL_TEST(test_udp_checksum_6(), "UDP-checksum 6");

	CALL_TEST(test_validate_icmp_integrity(), "ICMP-Checksums");

	CALL_TEST(test_inner_packet_validation4(), "Inner packet IPv4 Validation");
	CALL_TEST(test_inner_packet_validation6(), "Inner packet IPv6 Validation");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
