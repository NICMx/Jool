#include <linux/module.h>
#include <linux/printk.h>

#include "framework/unit_test.h"
#include "framework/skb_generator.h"

#include "mod/common/mapt.h"
#include "mod/common/packet.h"
#include "mod/common/db/fmr.h"
#include "mod/common/db/global.h"

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
	struct ipv6_prefix pool6;
	struct ipv6_prefix eui6p;
	struct mapping_rule bmr;
	int error;

	error = prefix6_parse("2001:db8:ffff::/64", &pool6);
	if (error)
		return error;

	error = xlator_init(&br, NULL, "BR", XT_MAPT | XF_IPTABLES, &pool6);
	if (error)
		return error;
	error = xlator_init(&ce, NULL, "CE", XT_MAPT | XF_IPTABLES, &pool6);
	if (error)
		return error;

	bmr.ea_bits_length = 16;
	error = prefix6_parse("2001:db8:12:3400::/56", &eui6p)
	    || prefix6_parse("2001:db8::/40", &bmr.prefix6)
	    || prefix4_parse("192.0.2.0/24", &bmr.prefix4)
	    || mapt_init(&br.globals.mapt, NULL, NULL, 6, 8)
	    || mapt_init(&ce.globals.mapt, &eui6p, &bmr, 6, 8);
	if (error)
		return error;

	return fmrt_add(br.mapt.fmrt, &bmr);
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

	xlation_init(&state, &br);
	if (!ASSERT_INT(0, create_skb4_tcp("10.2.3.4", 80, "192.0.2.18", 1232, 4, 64, &state.in.skb), "SKB creator"))
		return false;
	if (!ASSERT_INT(0, pkt_init_ipv4(&state, state.in.skb), "Pkt init"))
		return false;

	success  = ASSERT_INT(VERDICT_CONTINUE, translate_addrs46_mapt(&state, &src, &dst), "translate_addrs46_mapt()");
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

	success  = ASSERT_INT(VERDICT_CONTINUE, translate_addrs64_mapt(&state, &src.s_addr, &dst.s_addr), "translate_addrs64_mapt()");
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

	xlation_init(&state, &ce);
	if (!ASSERT_INT(0, create_skb4_tcp("192.0.2.18", 1232, "10.2.3.4", 80, 4, 64, &state.in.skb), "SKB creator"))
		return false;
	if (!ASSERT_VERDICT(CONTINUE, pkt_init_ipv4(&state, state.in.skb), "Pkt init"))
		return false;

	success  = ASSERT_VERDICT(CONTINUE, translate_addrs46_mapt(&state, &src, &dst), "translate_addrs46_mapt()");
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

	success  = ASSERT_VERDICT(CONTINUE, translate_addrs64_mapt(&state, &src.s_addr, &dst.s_addr), "translate_addrs64_mapt()");
	success &= ASSERT_ADDR4("10.2.3.4", &src, "Result source");
	success &= ASSERT_ADDR4("192.0.2.18", &dst, "Result destination");

	kfree_skb(state.in.skb);
	return success;
}

static bool check_variant(unsigned int a, unsigned int k,
		unsigned int r, unsigned int o,
		char const *test, unsigned int port, char const *expected)
{
	struct xlation state;
	struct mapping_rule rule;
	struct in_addr addr4;
	struct in6_addr addr6;
	bool success;

	memset(&state, 0, sizeof(state));
	state.jool.globals.mapt.prpf.a = a;
	state.jool.globals.mapt.prpf.k = k;

	memset(&rule, 0, sizeof(rule));
	rule.prefix6.addr.s6_addr32[0] = cpu_to_be32(0x20010db8);
	rule.prefix6.len = 64 - o;
	rule.prefix4.addr.s_addr = cpu_to_be32(0xc0000200);
	rule.prefix4.len = r;
	rule.ea_bits_length = o;

	if (!ASSERT_INT(0, str_to_addr4(test, &addr4), "IPv4 Address")) {
		pr_err("'%s' does not parse as an IPv4 address.\n", test);
		return false;
	}

	success = ASSERT_VERDICT(
		CONTINUE,
		rule_xlat46(
			&state,
			&rule,
			addr4.s_addr,
			cpu_to_be16(port),
			&addr6
		),
		"Function verdict"
	);
	success &= ASSERT_ADDR6(expected, &addr6, "IPv6 Address");

	return success;
}

/* `o + r = 32` implies `q = 0`, which I think in this case implies `k = 0` */
static bool o_plus_r_he_32(void)
{
	bool success = true;

	success &= check_variant(0,  0, 24, 8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant(16, 0, 24, 8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant(8,  0, 24, 8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant(7,  0, 24, 8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");
	success &= check_variant(9,  0, 24, 8, "192.0.2.89", 1234, "2001:db8:0:59:0:c000:259:0");

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

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
