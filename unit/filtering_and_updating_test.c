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
#include "filtering_and_updating.c"

static int bib_count_fn(struct bib_entry *bib, void *arg)
{
	int *count = arg;
	(*count)++;
	return 0;
}

static bool assert_bib_count(int expected, l4_protocol proto)
{
	int count = 0;
	bool success = true;

	success &= ASSERT_INT(0, bibdb_foreach(proto, bib_count_fn, &count, NULL), "count");
	success &= ASSERT_INT(expected, count, "BIB count");

	return success;
}

static bool assert_bib_exists(char *addr6, u16 port6, char *addr4, u16 port4,
		l4_protocol proto, unsigned int session_count)
{
	struct bib_entry *bib;
	struct ipv6_transport_addr tuple_addr;
	bool success = true;

	if (str_to_addr6(addr6, &tuple_addr.l3))
		return false;
	tuple_addr.l4 = port6;

	success &= ASSERT_INT(0, bibdb_get6(&tuple_addr, proto, &bib), "BIB exists");
	if (!success)
		return false;

	success &= ASSERT_ADDR6(addr6, &bib->ipv6.l3, "IPv6 address");
	success &= ASSERT_UINT(port6, bib->ipv6.l4, "IPv6 port");
	success &= ASSERT_ADDR4(addr4, &bib->ipv4.l3, "IPv4 address");
	/* The IPv4 port is unpredictable. */
	success &= ASSERT_BOOL(false, bib->is_static, "BIB is dynamic");
	success &= ASSERT_INT(session_count,
			atomic_read(&bib->refcounter.refcount) - 1,
			"BIB Session count");

	bibdb_return(bib);

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
	bool success = true;

	success = ASSERT_INT(0, sessiondb_foreach(proto, session_count_fn, &count, NULL, NULL), "count");
	success = ASSERT_INT(expected, count, "Session count");

	return success;
}

static bool assert_session_exists(unsigned char *remote_addr6, u16 remote_port6,
		unsigned char *local_addr6, u16 local_port6,
		unsigned char *local_addr4, u16 local_port4,
		unsigned char *remote_addr4, u16 remote_port4,
		l4_protocol proto, u_int8_t state)
{
	struct session_entry *session;
	struct tuple tuple6;
	int error;
	bool success = true;

	error = init_tuple6(&tuple6, remote_addr6, remote_port6, local_addr6, local_port6, proto);
	if (error)
		return false;

	success &= ASSERT_INT(0, sessiondb_get(&tuple6, NULL, NULL, &session), "Session exists");
	if (!success)
		return false;

	success &= ASSERT_ADDR6(remote_addr6, &session->remote6.l3, "remote addr6");
	success &= ASSERT_UINT(remote_port6, session->remote6.l4, "remote port6");
	success &= ASSERT_ADDR6(local_addr6, &session->local6.l3, "local addr6");
	success &= ASSERT_UINT(local_port6, session->local6.l4, "local port6");
	success &= ASSERT_ADDR4(local_addr4, &session->local4.l3, "local addr4");
	/* Local port4 is unpredictable. */
	success &= ASSERT_ADDR4(remote_addr4, &session->remote4.l3, "remote addr4");
	if (proto != L4PROTO_ICMP)
		success &= ASSERT_UINT(remote_port4, session->remote4.l4, "remote port4");
	success &= ASSERT_BOOL(true, session->bib != NULL, "Session's BIB");
	success &= ASSERT_INT(proto, session->l4_proto, "Session's l4 proto");
	success &= ASSERT_INT(state, session->state, "Session's state");

	session_return(session);

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
int invert_tuple(struct tuple *tuple)
{
	struct session_entry *session;

	if (sessiondb_get(tuple, NULL, NULL, &session)) {
		log_err("Could not find the session from the previous test.");
		return -EEXIST;
	}

	tuple->src.addr4 = session->remote4;
	tuple->dst.addr4 = session->local4;
	tuple->l3_proto = L3PROTO_IPV4;

	session_return(session);
	return 0;
}

static bool test_filtering_and_updating(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	struct tuple tuple;
	bool success = true;

	/* ICMP errors should pass happily, but not affect the tables. */
	if (init_tuple4(&tuple, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_TCP))
		return false;
	if (create_skb4_icmp_error(&tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, filtering_and_updating(&pkt, &tuple), "ICMP error");
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	kfree_skb(skb);
	if (!success)
		return false;

	/* This step should get rid of hairpinning loops. */
	if (init_tuple6(&tuple, "64:ff9b::1:2", 1212, "64:ff9b::3:4", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_DROP, filtering_and_updating(&pkt, &tuple), "Hairpinning");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	kfree_skb(skb);
	if (!success)
		return false;

	/* Other IPv6 packets should be processed normally. */
	if (init_tuple6(&tuple, "1::2", 1212, "3::3:4", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, filtering_and_updating(&pkt, &tuple), "IPv6 success");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_session_count(1, L4PROTO_UDP);

	kfree_skb(skb);
	if (!success)
		return false;

	/* Other IPv4 packets should be processed normally. */
	if (invert_tuple(&tuple))
		return false;
	if (create_skb4_udp(&tuple, &skb, 100, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, filtering_and_updating(&pkt, &tuple), "IPv4 success");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_session_count(1, L4PROTO_UDP);

	kfree_skb(skb);
	return success;
}

static bool test_udp(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	struct tuple tuple;
	bool success = true;

	/* An IPv4 packet attempts to be translated without state. */
	if (init_tuple4(&tuple, "0.0.0.4", 3434, "192.0.2.128", 1024, L4PROTO_UDP))
		return false;
	if (create_skb4_udp(&tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_ACCEPT, ipv4_simple(&pkt, &tuple), "result 1");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	kfree_skb(skb);

	/* IPv6 packet gets translated correctly. */
	if (init_tuple6(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_simple(&pkt, &tuple), "result 2");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_UDP, 1);
	success &= assert_session_count(1, L4PROTO_UDP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_UDP, 0);

	kfree_skb(skb);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	if (invert_tuple(&tuple))
		return false;
	if (create_skb4_udp(&tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv4_simple(&pkt, &tuple), "result 3");
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
	struct packet pkt;
	struct sk_buff *skb;
	struct tuple tuple;
	bool success = true;

	/* A IPv4 packet attempts to be translated without state */
	if (init_tuple4(&tuple, "0.0.0.4", 1024, "192.0.2.128", 1024, L4PROTO_ICMP))
		return false;
	if (create_skb4_icmp_info(&tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_ACCEPT, ipv4_simple(&pkt, &tuple), "result 1");
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	kfree_skb(skb);

	/* IPv6 packet and gets translated correctly. */
	if (init_tuple6(&tuple, "1::2", 1212, "3::4", 1212, L4PROTO_ICMP))
		return false;
	if (create_skb6_icmp_info(&tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_simple(&pkt, &tuple), "result 2");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.0.2.128", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	kfree_skb(skb);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	if (invert_tuple(&tuple))
		return false;
	if (create_skb4_icmp_info(&tuple, &skb, 16, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, ipv4_simple(&pkt, &tuple), "result 3");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.0.2.128", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	kfree_skb(skb);

	return success;
}

static bool test_tcp_closed_state_handle_6(void)
{
	struct tuple tuple6;
	struct packet pkt;
	struct sk_buff *skb;
	bool success = true;

	if (init_tuple6(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_TCP))
		return false;
	if (create_tcp_packet(&skb, L3PROTO_IPV6, true, false, false))
		return false;
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, tcp_closed_state(&pkt, &tuple6),
			"V6 syn-result");
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, V6_INIT);

	kfree_skb(skb);
	return success;
}

static bool test_tcp_closed_state_handle_4(void)
{
	struct session_entry *session;
	struct tuple tuple4;
	struct packet pkt;
	struct sk_buff *skb;
	struct tcphdr *hdr_tcp;
	bool success = true;

	if (init_tuple4(&tuple4, "5.6.7.8", 5678, "192.0.2.128", 8765, L4PROTO_TCP))
		return false;
	if (create_skb4_tcp(&tuple4, &skb, 100, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;
	hdr_tcp = tcp_hdr(skb);
	hdr_tcp->syn = true;
	hdr_tcp->rst = false;
	hdr_tcp->fin = false;

	success &= ASSERT_INT(VERDICT_STOLEN, tcp_closed_state(&pkt, &tuple4), "V4 syn-result");
	success &= ASSERT_INT(-ESRCH, sessiondb_get(&tuple4, NULL, NULL, &session), "V4 syn-session.");
	/*
	 * Well, it would be nice to test the packet was actually linked in pkt
	 * queue, but it's not possible using the current API.
	 * It's better to test it in graybox anyway.
	 */

	/* "skb" is kfreed when pktqueue is executed */
	return success;
}

/**
 * We'll just chain a handful of packets, since testing every combination would take forever and
 * the inner functions are tested in session db anyway.
 * The chain is V6 SYN --> V4 SYN --> V6 RST --> V6 SYN.
 */
static bool test_tcp(void)
{
	bool success = true;
	struct tuple tuple6, tuple4;
	struct packet pkt;
	struct sk_buff *skb;

	/* V6 SYN */
	if (init_tuple6(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_TCP))
		return false;
	if (create_tcp_packet(&skb, L3PROTO_IPV6, true, false, false))
		return false;
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, tcp(&pkt, &tuple6), "Closed-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, V6_INIT);

	kfree_skb(skb);

	/* V4 SYN */
	tuple4 = tuple6;
	if (invert_tuple(&tuple4))
		return false;
	if (create_tcp_packet(&skb, L3PROTO_IPV4, true, false, false))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, tcp(&pkt, &tuple4), "V6 init-result");
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
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, tcp(&pkt, &tuple6), "Established-result");
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
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	success &= ASSERT_INT(VERDICT_CONTINUE, tcp(&pkt, &tuple6), "Trans-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, ESTABLISHED);

	kfree_skb(skb);

	return success;
}

enum session_fate expire_fn(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static bool init(void)
{
	char *prefixes6[] = { "3::/96" };
	char *prefixes4[] = { "192.0.2.128/32" };

	if (config_init(false))
		goto config_fail;
	if (pool6_init(prefixes6, 1))
		goto pool6_fail;
	if (pool4db_init(16, prefixes4, 1))
		goto pool4_fail;
	if (filtering_init())
		goto filtering_fail;

	return true;

filtering_fail:
	pool4db_destroy();
pool4_fail:
	pool6_destroy();
pool6_fail:
	config_destroy();
config_fail:
	return false;
}

static void end(void)
{
	icmp64_pop();
	filtering_destroy();
	pool4db_destroy();
	pool6_destroy();
	config_destroy();
}

static int filtering_test_init(void)
{
	START_TESTS("Filtering and Updating");

	/* General */
	INIT_CALL_END(init(), test_filtering_and_updating(), end(), "core function");

	/* UDP */
	INIT_CALL_END(init(), test_udp(), end(), "UDP");

	/* ICMP */
	INIT_CALL_END(init(), test_icmp(), end(), "ICMP");

	/* TCP */
	INIT_CALL_END(init(), test_tcp_closed_state_handle_6(), end(), "TCP-CLOSED-6");
	INIT_CALL_END(init(), test_tcp_closed_state_handle_4(), end(), "TCP-CLOSED-4");
	INIT_CALL_END(init(), test_tcp(), end(), "test_tcp");

	END_TESTS;
}

static void filtering_test_exit(void)
{
	/* No code. */
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
