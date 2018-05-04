#include <linux/module.h>
#include <linux/kernel.h>

#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/mod/stateful/pool4/rfc6056.h"
#include "stateful/filtering_and_updating.c"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Unit tests for the Filtering module");

static struct xlator jool;

static int bib_count_fn(struct bib_entry *bib, bool is_static, void *arg)
{
	int *count = arg;
	(*count)++;
	return 0;
}

static bool assert_bib_count(int expected, l4_protocol proto)
{
	int counter = 0;
	__u64 stored;
	struct bib_foreach_func func = { .cb = bib_count_fn, .arg = &counter, };
	bool success = true;

	success &= ASSERT_INT(0, bib_foreach(jool.nat64.bib, proto, &func, NULL), "foreach result");
	success &= ASSERT_INT(expected, counter, "computed count");
	success &= ASSERT_INT(0, bib_count(jool.nat64.bib, proto, &stored), "count result");
	success &= ASSERT_U64((__u64)expected, stored, "stored count");

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
	int counter = 0;
	__u64 stored;
	struct session_foreach_func cb = { .cb = session_count_fn, .arg = &counter, };
	bool success = true;

	success &= ASSERT_INT(0, bib_foreach_session(jool.nat64.bib, proto, &cb, NULL), "foreach result");
	success &= ASSERT_INT(expected, counter, "computed count");
	success &= ASSERT_INT(0, bib_count_sessions(jool.nat64.bib, proto, &stored), "count result");
	success &= ASSERT_U64((__u64)expected, stored, "stored count");

	return success;
}

static int compare_session_foreach_cb(struct session_entry *session, void *arg)
{
	struct session_entry *expected = arg;
	bool success = true;

	if (!session_equals(expected, session))
		return 0; /* Still not found; keep foreaching. */

	success &= ASSERT_INT(expected->proto, session->proto, "Session's proto");
	success &= ASSERT_INT(expected->state, session->state, "Session's state");
	success &= ASSERT_BOOL(expected->timer_type, session->timer_type, "Session's timer type");
	success &= ASSERT_BOOL(true, session->update_time != 0, "Session's update time");
	success &= ASSERT_ULONG(expected->timeout, session->timeout, "Session's timeout");
	success &= ASSERT_INT(expected->has_stored, session->has_stored, "Session's stored");

	/*
	 * Success? Interrupt the foreach positively.
	 * Failure? Interrupt the foreach negatively.
	 */
	return success ? 1 : -EINVAL;
}

static int session_exists(struct session_entry *session)
{
	struct session_foreach_func func = {
			.cb = compare_session_foreach_cb,
			.arg = session,
	};
	/*
	 * This is the closest we have to a session finding function in the
	 * current API.
	 */
	return bib_foreach_session(jool.nat64.bib, session->proto, &func, NULL);
}

static bool assert_session_exists(char *src6_addr, u16 src6_port,
		char *dst6_addr, u16 dst6_port,
		char *src4_addr, u16 src4_port,
		char *dst4_addr, u16 dst4_port,
		l4_protocol proto, u_int8_t state,
		session_timer_type timer_type, unsigned long timeout)
{
	struct session_entry expected;
	int result;

	if (str_to_addr6(src6_addr, &expected.src6.l3))
		return false;
	if (str_to_addr6(dst6_addr, &expected.dst6.l3))
		return false;
	if (str_to_addr4(src4_addr, &expected.src4.l3))
		return false;
	if (str_to_addr4(dst4_addr, &expected.dst4.l3))
		return false;
	expected.src6.l4 = src6_port;
	expected.dst6.l4 = dst6_port;
	expected.src4.l4 = src4_port;
	expected.dst4.l4 = dst4_port;
	expected.proto = proto;
	expected.state = state;
	expected.timer_type = timer_type;
	expected.update_time = 0;
	expected.timeout = msecs_to_jiffies(timeout * 1000);
	expected.has_stored = false;

	result = session_exists(&expected);
	if (result > 0)
		return true;
	else if (result < 0)
		return false;
	return ASSERT_BOOL(1, 0, "session search");
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
static int invert_tuple(struct xlation *state)
{
	if (!state->entries.bib_set) {
		log_err("Session was expected to have a BIB entry.");
		return -ESRCH;
	}
	if (!state->entries.session_set) {
		log_err("Session was expected to have a session."); /* Lel */
		return -ESRCH;
	}

	state->in.tuple.src.addr4 = state->entries.session.dst4;
	state->in.tuple.dst.addr4 = state->entries.session.src4;
	state->in.tuple.l3_proto = L3PROTO_IPV4;
	return 0;
}

static bool test_filtering_and_updating(void)
{
	struct xlation state = { .jool = jool };
	struct sk_buff *skb;
	bool success = true;

	log_debug("ICMPv4 errors should succeed but not affect the tables.");
	if (init_tuple4(&state.in.tuple, "8.7.6.5", 8765, "192.0.2.128", 1024, L4PROTO_TCP))
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
	if (invert_tuple(&state))
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
			L4PROTO_UDP, ESTABLISHED,
			SESSION_TIMER_EST, UDP_DEFAULT);

	kfree_skb(skb);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	if (invert_tuple(&state))
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
			L4PROTO_UDP, ESTABLISHED,
			SESSION_TIMER_EST, UDP_DEFAULT);

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
			L4PROTO_ICMP, ESTABLISHED,
			SESSION_TIMER_EST, ICMP_DEFAULT);

	kfree_skb(skb);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	if (invert_tuple(&state))
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
			L4PROTO_ICMP, ESTABLISHED,
			SESSION_TIMER_EST, ICMP_DEFAULT);

	kfree_skb(skb);

	return success;
}

/**
 * We'll just chain a handful of packets, since testing every combination would
 * take forever and the inner functions are tested in session db anyway.
 * The chain is V6 SYN --> V4 SYN --> V6 RST --> V6 SYN.
 */
static bool test_tcp(void)
{
	struct xlation state = { .jool = jool };
	struct sk_buff *skb;
	bool success = true;

	log_debug("V6 SYN");
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
			L4PROTO_TCP, V6_INIT, SESSION_TIMER_TRANS, TCP_TRANS);

	kfree_skb(skb);

	log_debug("V4 SYN");
	if (invert_tuple(&state))
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
			L4PROTO_TCP, ESTABLISHED, SESSION_TIMER_EST, TCP_EST);

	kfree_skb(skb);

	log_debug("V6 RST");
	if (init_tuple6(&state.in.tuple, "1::2", 1212, "3::4", 3434, L4PROTO_TCP))
		return false;
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
			L4PROTO_TCP, TRANS, SESSION_TIMER_TRANS, TCP_TRANS);

	kfree_skb(skb);

	log_debug("V6 SYN");
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
			L4PROTO_TCP, ESTABLISHED, SESSION_TIMER_EST, TCP_EST);

	kfree_skb(skb);

	return success;
}

static int setup(void)
{
	int error;

	error = bib_setup();
	if (error)
		goto fail1;
	error = rfc6056_setup();
	if (error)
		goto fail2;
	error = xlator_setup();
	if (error)
		goto fail3;

	return 0;

fail3:
	rfc6056_teardown();
fail2:
	bib_teardown();
fail1:
	return error;
}

static void teardown(void)
{
	xlator_teardown();
	rfc6056_teardown();
	bib_teardown();
}

static int init(void)
{
	struct ipv6_prefix prefix6;
	struct pool4_entry_usr entry;
	int error;

	error = xlator_add(&jool);
	if (error)
		return error;

	error = str_to_addr6("3::", &prefix6.address);
	if (error)
		goto fail;
	prefix6.len = 96;
	error = pool6_add(jool.pool6, &prefix6);
	if (error)
		goto fail;

	entry.mark = 0;
	entry.iterations = 0;
	entry.flags = ITERATIONS_SET | ITERATIONS_INFINITE;
	error = str_to_addr4("192.0.2.128", &entry.range.prefix.address);
	if (error)
		goto fail;
	entry.range.prefix.len = 32;
	entry.range.ports.min = 1024;
	entry.range.ports.max = 1024;

	entry.proto = L4PROTO_TCP;
	error = pool4db_add(jool.nat64.pool4, &entry);
	if (error)
		goto fail;
	entry.proto = L4PROTO_UDP;
	error = pool4db_add(jool.nat64.pool4, &entry);
	if (error)
		goto fail;
	entry.proto = L4PROTO_ICMP;
	error = pool4db_add(jool.nat64.pool4, &entry);
	if (error)
		goto fail;

	return 0;

fail:
	xlator_put(&jool);
	xlator_rm();
	return error;
}

static void clean(void)
{
	icmp64_pop();
	xlator_put(&jool);
	xlator_rm();
}

static int filtering_test_init(void)
{
	struct test_group test = {
		.name = "Filtering and Updating",
		.setup_fn = setup,
		.teardown_fn = teardown,
		.init_fn = init,
		.clean_fn = clean,
	};

	if (test_group_begin(&test))
		return -EINVAL;

	test_group_test(&test, test_filtering_and_updating, "core function");
	test_group_test(&test, test_udp, "UDP");
	test_group_test(&test, test_icmp, "ICMP");
	test_group_test(&test, test_tcp, "test_tcp");

	return test_group_end(&test);
}

static void filtering_test_exit(void)
{
	/* No code. */
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
