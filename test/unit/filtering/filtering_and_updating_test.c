#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Unit tests for the Filtering module");

#include "nat64/common/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/mod/stateful/pool4/rfc6056.h"
#include "filtering_and_updating.c"

static struct xlator jool;

static int bib_count_fn(struct bib_entry *bib, bool is_static, void *arg)
{
	int *count = arg;
	(*count)++;
	return 0;
}

static bool assert_bib_count(int expected, l4_protocol proto)
{
	int count = 0;
	struct bib_foreach_func func = { .cb = bib_count_fn, .arg = &count, };
	bool success = true;

	success &= ASSERT_INT(0, bib_foreach(jool.nat64.bib, proto, &func, NULL), "count");
	success &= ASSERT_INT(expected, count, "BIB count");

	return success;
}

static bool assert_bib_exists(char *addr6, u16 port6, char *addr4, u16 port4,
		l4_protocol proto, unsigned int session_count)
{
	struct bib_entry bib;
	struct ipv6_transport_addr tuple_addr;
	bool success = true;

	if (str_to_addr6(addr6, &tuple_addr.l3))
		return false;
	tuple_addr.l4 = port6;

	success &= ASSERT_INT(0, bib_find6(jool.nat64.bib, proto, &tuple_addr, &bib), "BIB exists");
	if (!success)
		return false;

	success &= ASSERT_ADDR6(addr6, &bib.ipv6.l3, "IPv6 address");
	success &= ASSERT_UINT(port6, bib.ipv6.l4, "IPv6 port");
	success &= ASSERT_ADDR4(addr4, &bib.ipv4.l3, "IPv4 address");
	/* The IPv4 port is unpredictable. */
	success &= ASSERT_BOOL(proto, bib.l4_proto, "BIB proto");

	return success;
}

static int session_count_fn(struct session_entry *session, void *arg)
{
	int *count = arg;
	(*count)++;
	return 0;
}

static bool assert_session_count(int expected, l4_protocol proto)
{
	int count = 0;
	struct session_foreach_func cb = { .cb = session_count_fn, .arg = &count, };
	bool success = true;

	/* TODO maybe also compare the number to bib_count_sessions. */

	success = ASSERT_INT(0, bib_foreach_session(jool.nat64.bib, proto, &cb, NULL), "count");
	success = ASSERT_INT(expected, count, "Session count");

	return success;
}

static bool assert_session_exists(char *remote_addr6, u16 remote_port6,
		char *local_addr6, u16 local_port6,
		char *local_addr4, u16 local_port4,
		char *remote_addr4, u16 remote_port4,
		l4_protocol proto, u_int8_t state)
{
	struct bib_session result;
	struct tuple tuple6;
	int error;
	bool success = true;

	error = init_tuple6(&tuple6, remote_addr6, remote_port6, local_addr6, local_port6, proto);
	if (error)
		return false;

	success &= ASSERT_INT(0, bib_find(jool.nat64.bib, &tuple6, &result), "Session exists");
	if (!success)
		return false;

	success &= ASSERT_BOOL(true, result.bib_set, "bib set");
	success &= ASSERT_BOOL(true, result.session_set, "bib set");
	success &= ASSERT_ADDR6(remote_addr6, &result.session.src6.l3, "remote addr6");
	success &= ASSERT_UINT(remote_port6, result.session.src6.l4, "remote port6");
	success &= ASSERT_ADDR6(local_addr6, &result.session.dst6.l3, "local addr6");
	success &= ASSERT_UINT(local_port6, result.session.dst6.l4, "local port6");
	success &= ASSERT_ADDR4(local_addr4, &result.session.src4.l3, "local addr4");
	/* Local port4 is unpredictable. */
	success &= ASSERT_ADDR4(remote_addr4, &result.session.dst4.l3, "remote addr4");
	if (proto != L4PROTO_ICMP)
		success &= ASSERT_UINT(remote_port4, result.session.dst4.l4, "remote port4");
	success &= ASSERT_INT(proto, result.session.proto, "Session's l4 proto");
	success &= ASSERT_INT(state, result.session.state, "Session's state");
	success &= ASSERT_BOOL(true, result.session.established, "Session established?");
//	TODO
//	success &= ASSERT_INT(state, result.session.timeout, "Session's timeout");

	return success;
}

/**
 * Reinitializes @tuple (which is assumed to be an IPv6 tuple) into its
 * corresponding IPv4 tuple.
 *
 * It is assumed @tuple was already used in a IPv6 test. The "corresponding"
 * IPv4 tuple is the one that holds the inverse addresses in the opposite
 * direction.
 *
 * For example, if the previous packet was 1::1#22->3::3#44 and got translated
 * into 5.5.5.5#66->7.7.7.7#77, the "original" IPv6 tuple was 1::1#22->3::3#44,
 * and the corresponding IPv4 tuple is 7.7.7.7#77->5.5.5.5#66.
 */
static int invert_tuple(struct tuple *tuple)
{
	struct bib_session session;

	if (bib_find(jool.nat64.bib, tuple, &session)) {
		log_err("Could not find the session from the previous test.");
		return -EEXIST;
	}

	if (!session.bib_set) {
		log_err("Session was expected to have a BIB entry.");
		return -ESRCH;
	}
	if (!session.session_set) {
		log_err("Session was expected to have a session."); /* Lel */
		return -ESRCH;
	}

	tuple->src.addr4 = session.session.dst4;
	tuple->dst.addr4 = session.session.src4;
	tuple->l3_proto = L3PROTO_IPV4;

	return 0;
}

static bool test_filtering_and_updating(void)
{
	struct xlation state = { .jool = jool };
	struct sk_buff *skb;
	bool success = true;

	log_debug("ICMPv4 errors should succeed but not affect the tables.");
	if (init_tuple4(&state.in.tuple, "8.7.6.5", 8765, "192.0.2.128", 65000, L4PROTO_TCP))
		return false;
	if (create_skb4_icmp_error(&state.in.tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, filtering_and_updating(&state), "ICMP error");
	success &= assert_bib_count(0, L4PROTO_TCP);
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_TCP);
	success &= assert_session_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	kfree_skb(skb);
	if (!success)
		return false;

	log_debug("ICMPv6 errors should succeed but not affect the tables.");
	if (init_tuple6(&state.in.tuple, "1::2", 1212, "3::3:4", 3434, L4PROTO_TCP))
		return false;
	if (create_skb6_icmp_error(&state.in.tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, filtering_and_updating(&state), "ICMP error");
	success &= assert_bib_count(0, L4PROTO_TCP);
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_TCP);
	success &= assert_session_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	kfree_skb(skb);
	if (!success)
		return false;

	log_debug("Hairpinning loops should be dropped.");
	if (init_tuple6(&state.in.tuple, "3::1:2", 1212, "3::3:4", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&state.in.tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_DROP, filtering_and_updating(&state), "Hairpinning");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	kfree_skb(skb);
	if (!success)
		return false;

	log_debug("Packets not headed to pool6 must not be translated.");
	if (init_tuple6(&state.in.tuple, "1::2", 1212, "4::1", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&state.in.tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_ACCEPT, filtering_and_updating(&state), "Not pool6 packet");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	kfree_skb(skb);
	if (!success)
		return false;

	log_debug("Packets not headed to pool4 must not be translated.");
	if (init_tuple4(&state.in.tuple, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_UDP))
		return false;
	if (create_skb4_udp(&state.in.tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_ACCEPT, filtering_and_updating(&state), "Not pool4 packet");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	kfree_skb(skb);
	if (!success)
		return false;

	log_debug("Other IPv6 packets should survive validations.");
	if (init_tuple6(&state.in.tuple, "1::2", 1212, "3::3:4", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&state.in.tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, filtering_and_updating(&state), "IPv6 success");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_session_count(1, L4PROTO_UDP);

	kfree_skb(skb);
	if (!success)
		return false;

	log_debug("Other IPv4 packets should survive validations.");
	if (invert_tuple(&state.in.tuple))
		return false;
	if (create_skb4_udp(&state.in.tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, filtering_and_updating(&state), "IPv4 success");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_session_count(1, L4PROTO_UDP);

	kfree_skb(skb);
	return success;
}

static bool test_udp(void)
{
	struct xlation state = { .jool = jool };
	struct sk_buff *skb;
	bool success = true;

	/* An IPv4 packet attempts to be translated without state. */
	if (init_tuple4(&state.in.tuple, "0.0.0.4", 3434, "192.0.2.128", 1024, L4PROTO_UDP))
		return false;
	if (create_skb4_udp(&state.in.tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_ACCEPT, ipv4_simple(&state), "result 1");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	kfree_skb(skb);

	/* IPv6 packet gets translated correctly. */
	if (init_tuple6(&state.in.tuple, "1::2", 1212, "3::4", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&state.in.tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_simple(&state), "result 2");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_UDP, 1);
	success &= assert_session_count(1, L4PROTO_UDP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_UDP, 0);

	kfree_skb(skb);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	if (invert_tuple(&state.in.tuple))
		return false;
	if (create_skb4_udp(&state.in.tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv4_simple(&state), "result 3");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_UDP, 1);
	success &= assert_session_count(1, L4PROTO_UDP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_UDP, 0);

	kfree_skb(skb);

	return success;
}

static bool test_icmp(void)
{
	struct xlation state = { .jool = jool };
	struct sk_buff *skb;
	bool success = true;

	/* A IPv4 packet attempts to be translated without state */
	if (init_tuple4(&state.in.tuple, "0.0.0.4", 1024, "192.0.2.128", 1024, L4PROTO_ICMP))
		return false;
	if (create_skb4_icmp_info(&state.in.tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_ACCEPT, ipv4_simple(&state), "result 1");
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	kfree_skb(skb);

	/* IPv6 packet and gets translated correctly. */
	if (init_tuple6(&state.in.tuple, "1::2", 1212, "3::4", 1212, L4PROTO_ICMP))
		return false;
	if (create_skb6_icmp_info(&state.in.tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_simple(&state), "result 2");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.0.2.128", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	kfree_skb(skb);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	if (invert_tuple(&state.in.tuple))
		return false;
	if (create_skb4_icmp_info(&state.in.tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv4_simple(&state), "result 3");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.0.2.128", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	kfree_skb(skb);

	return success;
}

/**
 * We'll just chain a handful of packets, since testing every combination would take forever and
 * the inner functions are tested in session db anyway.
 * The chain is V6 SYN --> V4 SYN --> V6 RST --> V6 SYN.
 */
static bool test_tcp(void)
{
	struct xlation state = { .jool = jool };
	struct sk_buff *skb;
	bool success = true;

	/* V6 SYN */
	if (init_tuple6(&state.in.tuple, "1::2", 1212, "3::4", 3434, L4PROTO_TCP))
		return false;
	if (create_tcp_packet(&skb, L3PROTO_IPV6, true, false, false))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_tcp(&state), "Closed-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, V6_INIT);

	kfree_skb(skb);

	/* V4 SYN */
	if (invert_tuple(&state.in.tuple))
		return false;
	if (create_tcp_packet(&skb, L3PROTO_IPV4, true, false, false))
		return false;
	if (pkt_init_ipv4(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv4_tcp(&state), "V6 init-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, ESTABLISHED);

	kfree_skb(skb);

	/* V6 RST */
	if (create_tcp_packet(&skb, L3PROTO_IPV6, false, true, false))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_tcp(&state), "Established-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, TRANS);

	kfree_skb(skb);

	/* V6 SYN */
	if (create_tcp_packet(&skb, L3PROTO_IPV6, true, false, false))
		return false;
	if (pkt_init_ipv6(&state.in, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_tcp(&state), "Trans-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, ESTABLISHED);

	kfree_skb(skb);

	return success;
}

static bool init(void)
{
	struct ipv6_prefix prefix6;
	struct ipv4_range range;

	if (bib_init())
		return false;
	if (rfc6056_init())
		goto fail2;

	if (xlator_init())
		goto fail3;
	if (xlator_add(&jool))
		goto fail4;

	if (str_to_addr6("3::", &prefix6.address))
		goto fail5;
	prefix6.len = 96;
	if (pool6_add(jool.pool6, &prefix6))
		goto fail5;

	if (str_to_addr4("192.0.2.128", &range.prefix.address))
		goto fail5;
	range.prefix.len = 32;
	range.ports.min = 0;
	range.ports.max = 65535;

	if (pool4db_add(jool.nat64.pool4, 0, L4PROTO_TCP, &range))
		goto fail5;
	if (pool4db_add(jool.nat64.pool4, 0, L4PROTO_UDP, &range))
		goto fail5;
	if (pool4db_add(jool.nat64.pool4, 0, L4PROTO_ICMP, &range))
		goto fail5;

	return true;

fail5:
	xlator_put(&jool);
fail4:
	xlator_destroy();
fail3:
	rfc6056_destroy();
fail2:
	bib_destroy();
	return false;
}

static void end(void)
{
	icmp64_pop();
	xlator_put(&jool);
	xlator_destroy();
	rfc6056_destroy();
	bib_destroy();
}

static int filtering_test_init(void)
{
	START_TESTS("Filtering and Updating");

	INIT_CALL_END(init(), test_filtering_and_updating(), end(), "core function");
	INIT_CALL_END(init(), test_udp(), end(), "UDP");
	INIT_CALL_END(init(), test_icmp(), end(), "ICMP");
	INIT_CALL_END(init(), test_tcp(), end(), "test_tcp");

	END_TESTS;
}

static void filtering_test_exit(void)
{
	/* No code. */
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
