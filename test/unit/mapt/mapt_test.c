#include <linux/module.h>
#include <linux/printk.h>

#include "framework/unit_test.h"
#include "framework/skb_generator.h"

#include "mod/common/mapt.h"
#include "mod/common/packet.h"
#include "mod/common/db/global.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("MAP-T address translation module test.");

static struct xlator br;
static struct xlator ce;

void jstat_inc(struct jool_stats *stats, enum jool_stat_id stat)
{
	/* No code */
}

static int setup_mapt(void)
{
	struct ipv6_prefix pool6;
	struct ipv6_prefix eui6p;
	struct mapping_rule bmr;
	int error;

	error = prefix6_parse("2001:db8:ffff::/64", &pool6);
	if (error)
		return error;

	memset(&br.globals, 0, sizeof(br.globals));
	br.globals.pool6.prefix = pool6;
	br.globals.pool6.set = true;
	memset(&ce.globals, 0, sizeof(ce.globals));
	ce.globals.pool6.prefix = pool6;
	ce.globals.pool6.set = true;
	bmr.ea_bits_length = 16;

	return prefix6_parse("2001:db8:12:3400::/56", &eui6p)
	    || prefix6_parse("2001:db8::/40", &bmr.prefix6)
	    || prefix4_parse("192.0.2.0/24", &bmr.prefix4)
	    || mapt_init(&br.globals.mapt, NULL, NULL, 6, 8)
	    || mapt_init(&ce.globals.mapt, &eui6p, &bmr, 6, 8);
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

int init_module(void)
{
	struct test_group test = {
		.name = "MAP-T",
		.setup_fn = setup_mapt,
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, br46, "BR address translation, 4->6");
	test_group_test(&test, br64, "BR address translation, 6->4");
	test_group_test(&test, ce46, "CE address translation, 4->6");
	test_group_test(&test, ce64, "CE address translation, 6->4");

	return test_group_end(&test);
}

void cleanup_module(void)
{
	/* No code. */
}
