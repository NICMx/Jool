#include <linux/module.h>
#include "nat64/mod/packet.h"

#include "nat64/unit/unit_test.h"
#include "nat64/unit/types.h"
#include "nat64/unit/skb_generator.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Packet test");


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
	success &= assert_equals_csum(cpu_to_be16(0xa139), udp_hdr(skb1)->check, "Computed IPv4 csum");

	kfree_skb(skb1);

	if (create_skb_ipv4_udp_fragment(&pair4, &skb1, 8) != 0)
		return false;
	ip_hdr(skb1)->frag_off = build_ipv4_frag_off_field(true, true, 0);
	if (create_skb_ipv4_udp_fragment(&pair4, &skb2, 8) != 0)
		return false;
	ip_hdr(skb2)->frag_off = build_ipv4_frag_off_field(true, false, 16);

	skb1->next = skb2;
	skb2->prev = skb1;

	udp_hdr(skb1)->check = cpu_to_be16(0);
	success &= assert_equals_int(0, fix_checksums_ipv4(skb1), "Function result 3");
	/* Zero-checksums should be computed. */
	/* TODO is this checksum correct? */
	success &= assert_equals_csum(cpu_to_be16(0xdfc3), udp_hdr(skb1)->check, "Frag IPv4 csum");

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

int init_module(void)
{
	START_TESTS("Packet");

	CALL_TEST(test_function_is_dont_fragment_set(), "Dont fragment getter");
	CALL_TEST(test_function_is_more_fragments_set(), "More fragments getter");
	CALL_TEST(test_function_build_ipv4_frag_off_field(), "Generate frag offset + flags function");

	CALL_TEST(test_udp_checksum_4(), "UDP-checksum 4");
	CALL_TEST(test_udp_checksum_6(), "UDP-checksum 6");

	CALL_TEST(test_validate_icmp_integrity(), "ICMP-Checksums");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
