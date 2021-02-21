#include <linux/module.h>
#include <linux/printk.h>

#include "framework/address.h"
#include "framework/unit_test.h"
#include "framework/skb_generator.h"

#include "mod/common/mapt.h"
#include "mod/common/packet.h"
#include "mod/common/db/fmr.h"
#include "mod/common/db/global.h"
#include "mod/common/steps/determine_incoming_tuple.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("MAP-T address translation module test.");

static struct xlator br;
static struct xlator ce;

verdict rule_xlat46(struct xlation *state, struct mapping_rule *rule,
		__be32 in, unsigned int port,
		struct in6_addr *out);

static int setup_mapt(void)
{
	struct jool_globals globals;
	int error;

	error = globals_init(&globals, XT_MAPT, NULL);
	if (error)
		return error;

	globals.pool6.set = true;
	error = prefix6_parse("2001:db8:ffff::/64", &globals.pool6.prefix);
	if (error)
		return error;

	error = xlator_init(&br, NULL, "BR", XT_MAPT | XF_IPTABLES, &globals, NULL);
	if (error)
		return error;
	error = xlator_init(&ce, NULL, "CE", XT_MAPT | XF_IPTABLES, &globals, NULL);
	if (error)
		return error;

	memset(&br.globals.mapt, 0, sizeof(br.globals.mapt));
	br.globals.mapt.type = MAPTYPE_BR;

	memset(&ce.globals.mapt, 0, sizeof(ce.globals.mapt));
	ce.globals.mapt.type = MAPTYPE_CE;
	ce.globals.mapt.eui6p.set = true;
	error = prefix6_parse("2001:db8:12:3400::/56", &ce.globals.mapt.eui6p.prefix);
	if (error)
		return error;
	error = prefix6_parse("2001:db8::/40", &ce.globals.mapt.bmr.rule.prefix6);
	if (error)
		return error;
	error = prefix4_parse("192.0.2.0/24", &ce.globals.mapt.bmr.rule.prefix4);
	if (error)
		return error;
	ce.globals.mapt.bmr.rule.o = 16;
	ce.globals.mapt.bmr.rule.a = 6;

	ce.globals.debug = true;

	return fmrt_add(br.mapt.fmrt, &ce.globals.mapt.bmr.rule, NULL);
}

void teardown_mapt(void)
{
	xlator_put(&br);
	xlator_put(&ce);
}

/* RFC7599 Appendix A Example 2 */
static bool br46(void)
{
	struct xlation state;
	struct in6_addr src;
	struct in6_addr dst;
	bool success;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	xlation_init(&state, &br);
	if (!ASSERT_INT(0, create_skb4_tcp("10.2.3.4", 80, "192.0.2.18", 1232, 4, 64, &state.in.skb), "SKB creator"))
		return false;
	if (!ASSERT_INT(0, pkt_init_ipv4(&state, state.in.skb), "Pkt init"))
		return false;
	if (!ASSERT_VERDICT(CONTINUE, determine_in_tuple(&state), "DIT"))
		return false;

	success  = ASSERT_VERDICT(CONTINUE, translate_addrs46_mapt(&state, &src, &dst, true), "translate_addrs46_mapt()");
	success &= ASSERT_ADDR6("2001:db8:ffff:0:a:203:0400::", &src, "Result source");
	success &= ASSERT_ADDR6("2001:db8:12:3400::c000:212:34", &dst, "Result destination");

	kfree_skb(state.in.skb);
	return success;
}

static bool br64(void)
{
	struct xlation state;
	struct in_addr src;
	struct in_addr dst;
	bool success;

	xlation_init(&state, &br);
	if (!ASSERT_INT(0, create_skb6_tcp("2001:db8:12:3400::c000:212:34", 1232, "2001:db8:ffff:0:a:203:0400::", 80, 4, 64, &state.in.skb), "SKB creator"))
		return false;
	if (!ASSERT_INT(0, pkt_init_ipv6(&state, state.in.skb), "Pkt init"))
		return false;

	success  = ASSERT_VERDICT(CONTINUE, translate_addrs64_mapt(&state, &src.s_addr, &dst.s_addr, true), "translate_addrs64_mapt()");
	success &= ASSERT_ADDR4("192.0.2.18", &src, "Result source");
	success &= ASSERT_ADDR4("10.2.3.4", &dst, "Result destination");

	kfree_skb(state.in.skb);
	return success;
}

/* RFC7599 Appendix A Example 3 */
static bool ce46(void)
{
	struct xlation state;
	struct in6_addr src;
	struct in6_addr dst;
	bool success;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	xlation_init(&state, &ce);
	if (!ASSERT_INT(0, create_skb4_tcp("192.0.2.18", 1232, "10.2.3.4", 80, 4, 64, &state.in.skb), "SKB creator"))
		return false;
	if (!ASSERT_VERDICT(CONTINUE, pkt_init_ipv4(&state, state.in.skb), "Pkt init"))
		return false;
	if (!ASSERT_VERDICT(CONTINUE, determine_in_tuple(&state), "DIT"))
		return false;

	success  = ASSERT_VERDICT(CONTINUE, translate_addrs46_mapt(&state, &src, &dst, true), "translate_addrs46_mapt()");
	success &= ASSERT_ADDR6("2001:db8:12:3400::c000:212:34", &src, "Result source");
	success &= ASSERT_ADDR6("2001:db8:ffff:0:a:203:400::", &dst, "Result destination");

	kfree_skb(state.in.skb);
	return success;
}

static bool ce64(void)
{
	struct xlation state;
	struct in_addr src;
	struct in_addr dst;
	bool success;

	xlation_init(&state, &ce);
	if (!ASSERT_INT(0, create_skb6_tcp("2001:db8:ffff:0:a:203:400::", 80, "2001:db8:12:3400::c000:212:34", 1232, 4, 64, &state.in.skb), "SKB creator"))
		return false;
	if (!ASSERT_VERDICT(CONTINUE, pkt_init_ipv6(&state, state.in.skb), "Pkt init"))
		return false;

	success  = ASSERT_VERDICT(CONTINUE, translate_addrs64_mapt(&state, &src.s_addr, &dst.s_addr, true), "translate_addrs64_mapt()");
	success &= ASSERT_ADDR4("10.2.3.4", &src, "Result source");
	success &= ASSERT_ADDR4("192.0.2.18", &dst, "Result destination");

	kfree_skb(state.in.skb);
	return success;
}

static unsigned int bmr_prefix4;

static bool check_variant(unsigned int a, unsigned int r, unsigned int o,
		char const *test, unsigned int port, char const *expected)
{
	struct xlation state;
	struct mapping_rule rule;
	struct in_addr addr4;
	struct in6_addr addr6;
	bool success;

	xlation_init(&state, &ce);

	memset(&rule, 0, sizeof(rule));
	rule.prefix6.addr.s6_addr32[0] = cpu_to_be32(0x20010db8);
	rule.prefix6.len = 64 - o;
	rule.prefix4.addr.s_addr = cpu_to_be32(bmr_prefix4);
	rule.prefix4.len = r;
	rule.o = o;
	rule.a = a;

	if (!ASSERT_INT(0, str_to_addr4(test, &addr4), "IPv4 Address")) {
		pr_err("'%s' does not parse as an IPv4 address.\n", test);
		return false;
	}
	memset(&addr6, 0, sizeof(addr6));

	pr_info("a:%u r:%u o:%u %s:%u\n", a, r, o, test, port);

	success = ASSERT_VERDICT(
		CONTINUE,
		rule_xlat46(&state, &rule, addr4.s_addr, port, &addr6),
		"Function verdict"
	);
	success &= ASSERT_ADDR6(expected, &addr6, "IPv6 Address");

	return success;
}

/* "he" stands for "higher or equal." */
static bool o_plus_r_he_32(void)
{
	bool success = true;

	bmr_prefix4 = 0xc0000200;

	/*
	 * See rfc7597#section-5.2.
	 * This is the train of thought that led to these tests:
	 *
	 * When `o + r = 32`, `o = p` and therefore `q = 0`. (ie. the PSID is
	 * included in the EA-bits only if it contributes routing information.)
	 *
	 * When `o + r > 32`,
	 *
	 *	p = 32 - r (By RFC, section 5.2)
	 *	o = p + q (By definition)
	 *	Hence o + r = 32 + q
	 *
	 * This doesn't contradict our observations from `o + r = 32`, so we can
	 * generalize this as "if `o + r >= 32`, then `o + r = 32 + q`."
	 *
	 * So, because `k = q`, these tests are all designed around
	 * `o + r = 32 + k`.
	 */

	/*
	 * 0 <= o <= 48
	 * 0 <= r <= 32
	 * 0 <= a <= 16
	 * 0 <= k = q <= 16
	 * 0 <= m <= 16
	 */

	/*
	 * First, pivot around r = 24.
	 * (r = 24, try several combinations of a/k/m, use above equation to
	 * infer o.)
	 * (The commented columns are k and m.)
	 */
	success &= check_variant( 0, /*  0, 16, */ 24,  8, "192.0.2.89", 1234, "2001:db8:0:59::c000:259:0");
	success &= check_variant( 0, /* 16,  0, */ 24, 24, "192.0.2.89", 1234, "2001:db8:59:4d2::c000:259:4d2");
	success &= check_variant(16, /*  0,  0, */ 24,  8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant( 0, /*  8,  8, */ 24, 16, "192.0.2.89", 1234, "2001:db8:0:5904:0:c000:259:4");
	success &= check_variant( 8, /*  0,  8, */ 24,  8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant( 8, /*  8,  0, */ 24, 16, "192.0.2.89", 1234, "2001:db8:0:59d2:0:c000:259:d2");
	success &= check_variant( 0, /*  7,  9, */ 24, 15, "192.0.2.89", 1234, "2001:db8:0:2c82:0:c000:259:2");
	success &= check_variant( 7, /*  0,  9, */ 24,  8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant( 7, /*  9,  0, */ 24, 17, "192.0.2.89", 1234, "2001:db8:0:b2d2:0:c000:259:d2");
	success &= check_variant( 0, /*  9,  7, */ 24, 17, "192.0.2.89", 1234, "2001:db8:0:b209:0:c000:259:9");
	success &= check_variant( 9, /*  0,  7, */ 24,  8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant( 9, /*  7,  0, */ 24, 15, "192.0.2.89", 1234, "2001:db8:0:2cd2:0:c000:259:52");
	success &= check_variant( 6, /*  8,  2, */ 24, 16, "192.0.2.89", 1234, "2001:db8:0:5934:0:c000:259:34");

	/*
	 * Now, pivot around o = 16.
	 * (o = 16, try several combinations of a/k/m, use above equation to
	 * infer r.)
	 */
	success &= check_variant( 0, /*  0, 16, */ 16, 16, "192.0.2.89", 1234, "2001:db8:0:259::c000:259:0");
	success &= check_variant( 0, /* 16,  0, */ 32, 16, "192.0.2.89", 1234, "2001:db8:0:4d2::c000:259:4d2");
	success &= check_variant(16, /*  0,  0, */ 16, 16, "192.0.2.89", 1234, "2001:db8:0:259::c000:259:0");
//	success &= check_variant( 0, /*  8,  8, */ 24, 16, "192.0.2.89", 1234, "2001:db8:0:____::c000:259:____");
	success &= check_variant( 8, /*  0,  8, */ 16, 16, "192.0.2.89", 1234, "2001:db8:0:259::c000:259:0");
//	success &= check_variant( 8, /*  8,  0, */ 24, 16, "192.0.2.89", 1234, "2001:db8:0:____::c000:259:____");
	success &= check_variant( 0, /*  7,  9, */ 23, 16, "192.0.2.89", 1234, "2001:db8:0:2c82::c000:259:2");
	success &= check_variant( 7, /*  0,  9, */ 16, 16, "192.0.2.89", 1234, "2001:db8:0:259::c000:259:0");
	success &= check_variant( 7, /*  9,  0, */ 25, 16, "192.0.2.89", 1234, "2001:db8:0:b2d2::c000:259:d2");
	success &= check_variant( 0, /*  9,  7, */ 25, 16, "192.0.2.89", 1234, "2001:db8:0:b209::c000:259:09");
	success &= check_variant( 9, /*  0,  7, */ 16, 16, "192.0.2.89", 1234, "2001:db8:0:259::c000:259:0");
	success &= check_variant( 9, /*  7,  0, */ 23, 16, "192.0.2.89", 1234, "2001:db8:0:2cd2::c000:259:52");
//	success &= check_variant( 6, /*  8,  2, */ 24, 16, "192.0.2.89", 1234, "2001:db8:0:____::c000:259:____");

	return success;
}

/* "lt" stands for "less than." */
static bool o_plus_r_lt_32(void)
{
	bool success = true;

	bmr_prefix4 = 0xc6336400;

	/*
	 * o + r < 32
	 *
	 * 0 <= o = p < 32
	 * 0 <= r < 32
	 * q = 0
	 * a, k and m do not exist
	 */

	success &= check_variant(0,  8,  8, "198.51.100.89", 1234, "2001:db8:0:33:6459:c633:6459:0");
	success &= check_variant(0, 16, 15, "198.51.100.89", 1234, "2001:db8:0:322c:8000:c633:6459:0");
	success &= check_variant(0, 15, 16, "198.51.100.89", 1234, "2001:db8:0:b22c:8000:c633:6459:0");
	success &= check_variant(0,  0,  0, "198.51.100.89", 1234, "2001:db8::c633:6459:6459:0");
	success &= check_variant(0,  0, 31, "198.51.100.89", 1234, "2001:db8:6319:b22c:8000:c633:6459:0");
	success &= check_variant(0, 31,  0, "198.51.100.89", 1234, "2001:db8::8000:c633:6459:0");

	return success;
}

int init_module(void)
{
	struct test_group test = {
		.name = "MAP-T",
		.setup_fn = setup_mapt,
		.teardown_fn = teardown_mapt,
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, br46, "BR address translation, 4->6");
	test_group_test(&test, br64, "BR address translation, 6->4");
	test_group_test(&test, ce46, "CE address translation, 4->6");
	test_group_test(&test, ce64, "CE address translation, 6->4");
	test_group_test(&test, o_plus_r_he_32, "o + r >= 32");
	test_group_test(&test, o_plus_r_lt_32, "o + r < 32");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
