#include <linux/module.h>
#include "nat64/mod/packet.h"

#include "nat64/unit/unit_test.h"

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

	success &= assert_equals_u16(0x407b, be16_to_cpu(build_ipv4_frag_off_field(1, 0, 123)),
			"Simple 1");
	success &= assert_equals_u16(0x2159, be16_to_cpu(build_ipv4_frag_off_field(0, 1, 345)),
			"Simple 2");

	return success;
}

int init_module(void)
{
	START_TESTS("Packet");

	CALL_TEST(test_function_is_dont_fragment_set(), "Dont fragment getter");
	CALL_TEST(test_function_is_more_fragments_set(), "More fragments getter");
	CALL_TEST(test_function_build_ipv4_frag_off_field(), "Generate frag offset + flags function");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
