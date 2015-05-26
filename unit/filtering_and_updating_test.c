#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/printk.h> /* pr_* */
#include <linux/ipv6.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Unit tests for the Filtering module");
MODULE_ALIAS("nat64_test_filtering");

#include "nat64/common/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/session.h"
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
	success &= ASSERT_UINT(port4, bib->ipv4.l4, "IPv4 port");
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

	success &= ASSERT_INT(0, sessiondb_get(&tuple6, NULL, &session), "Session exists");
	if (!success)
		return false;

	success &= ASSERT_ADDR6(remote_addr6, &session->remote6.l3, "remote addr6");
	success &= ASSERT_UINT(remote_port6, session->remote6.l4, "remote port6");
	success &= ASSERT_ADDR6(local_addr6, &session->local6.l3, "local addr6");
	success &= ASSERT_UINT(local_port6, session->local6.l4, "local port6");
	success &= ASSERT_ADDR4(local_addr4, &session->local4.l3, "local addr4");
	success &= ASSERT_UINT(local_port4, session->local4.l4, "local port4");
	success &= ASSERT_ADDR4(remote_addr4, &session->remote4.l3, "remote addr4");
	success &= ASSERT_UINT(remote_port4, session->remote4.l4, "remote port4");
	success &= ASSERT_BOOL(true, session->bib != NULL, "Session's BIB");
	success &= ASSERT_INT(proto, session->l4_proto, "Session's l4 proto");
	success &= ASSERT_INT(state, session->state, "Session's state");

	session_return(session);

	return success;
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

//	/* Packets not belonging to the IPv6 pool must not be translated. */
//	if (init_tuple6(&tuple, "1::2", 1212, "2001:db8:c0ca:1::1", 3434,
//			L4PROTO_UDP))
//		return false;
//	if (create_skb6_udp(&tuple, &skb, 100, 32))
//		return false;
//	if (pkt_init_ipv6(&pkt, skb))
//		return false;
//
//	success &= ASSERT_INT(VERDICT_DROP, filtering_and_updating(&pkt, &tuple), "Not pool6 packet");
//	success &= assert_bib_count(0, L4PROTO_UDP);
//	success &= assert_session_count(0, L4PROTO_UDP);
//
//	kfree_skb(skb);
//	if (!success)
//		return false;
//
//	/* Packets not belonging to the IPv4 must not be translated. */
//	if (init_tuple4(&tuple, "192.168.100.44", 8765, "5.6.7.8", 5678,
//			L4PROTO_UDP))
//		return false;
//	if (create_skb4_udp(&tuple, &skb, 100, 32))
//		return false;
//	if (pkt_init_ipv4(&pkt, skb))
//		return false;
//
//	success &= ASSERT_INT(VERDICT_DROP, filtering_and_updating(&pkt, &tuple), "Not pool4 packet");
//	success &= assert_bib_count(0, L4PROTO_UDP);
//	success &= assert_session_count(0, L4PROTO_UDP);
//
//	kfree_skb(skb);
//	if (!success)
//		return false;

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
	if (init_tuple4(&tuple, "0.3.0.4", 3434, "192.0.2.128", 1024, L4PROTO_UDP))
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
	struct packet pkt6, pkt4;
	struct sk_buff *skb6, *skb4;
	struct tuple tuple6, tuple4;
	bool success = true;

	/* Prepare the IPv6 packet. */
	if (init_tuple6(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_UDP))
		return false;
	if (create_skb6_udp(&tuple6, &skb6, 16, 32))
		return false;
	if (pkt_init_ipv6(&pkt6, skb6))
		return false;

	/* Prepare the IPv4 packet. */
	if (init_tuple4(&tuple4, "0.0.0.4", 3434, "192.0.2.128", 1024, L4PROTO_UDP))
		return false;
	if (create_skb4_udp(&tuple4, &skb4, 16, 32))
		return false;
	if (pkt_init_ipv4(&pkt4, skb4))
		return false;

	/* A IPv4 packet attempts to be translated without state */
	success &= ASSERT_INT(VERDICT_ACCEPT, ipv4_simple(&pkt4, &tuple4), "result 1");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	/* IPv6 packet gets translated correctly. */
	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_simple(&pkt6, &tuple6), "result 2");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_UDP, 1);
	success &= assert_session_count(1, L4PROTO_UDP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_UDP, 0);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	success &= ASSERT_INT(VERDICT_CONTINUE, ipv4_simple(&pkt4, &tuple4), "result 3");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_UDP, 1);
	success &= assert_session_count(1, L4PROTO_UDP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 1024, "0.0.0.4", 3434,
			L4PROTO_UDP, 0);

	/* Quit */
	kfree_skb(skb6);
	kfree_skb(skb4);
	return success;
}

static bool test_icmp(void)
{
	struct packet pkt6, pkt4;
	struct sk_buff *skb6, *skb4;
	struct tuple tuple6, tuple4;
	bool success = true;

	/* Prepare the IPv6 packet. */
	if (init_tuple6(&tuple6, "1::2", 1212, "3::4", 1212, L4PROTO_ICMP))
		return false;
	if (create_skb6_icmp_info(&tuple6, &skb6, 16, 32))
		return false;
	if (pkt_init_ipv6(&pkt6, skb6))
		return false;

	/* Prepare the IPv4 packet. */
	if (init_tuple4(&tuple4, "0.0.0.4", 1024, "192.0.2.128", 1024, L4PROTO_ICMP))
		return false;
	if (create_skb4_icmp_info(&tuple4, &skb4, 16, 32))
		return false;
	if (pkt_init_ipv4(&pkt4, skb4))
		return false;

	/* A IPv4 packet attempts to be translated without state */
	success &= ASSERT_INT(VERDICT_ACCEPT, ipv4_simple(&pkt4, &tuple4), "result 1");
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	/* IPv6 packet and gets translated correctly. */
	success &= ASSERT_INT(VERDICT_CONTINUE, ipv6_simple(&pkt6, &tuple6), "result 2");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.0.2.128", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	success &= ASSERT_INT(VERDICT_CONTINUE, ipv4_simple(&pkt4, &tuple4), "result 3");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.0.2.128", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.0.2.128", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	/* Quit */
	kfree_skb(skb6);
	kfree_skb(skb4);
	return success;
}

static bool test_tcp_closed_state_handle_6(void)
{
	struct session_entry *session;
	struct tuple tuple6;
	struct packet pkt;
	struct sk_buff *skb;
	bool success = true;

	/* Prepare */
	if (init_tuple6(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_TCP))
		return false;
	if (create_tcp_packet(&skb, L3PROTO_IPV6, true, false, false))
		return false;
	if (pkt_init_ipv6(&pkt, skb))
		return false;

	/* Evaluate */
	success &= ASSERT_INT(VERDICT_CONTINUE, tcp_closed_state(&pkt, &tuple6),
			"V6 syn-result");

	/* Validate */
	success &= ASSERT_INT(0, sessiondb_get(&tuple6, NULL, &session), "V6 syn-session.");
	if (success)
		success &= ASSERT_UINT(V6_INIT, session->state, "V6 syn-state");

	kfree_skb(skb);
	return success;
}

static bool test_tcp_closed_state_handle_4(void)
{
	struct session_entry *session, *tmp;
	struct tuple tuple4;
	struct packet pkt;
	struct sk_buff *skb;
	struct tcphdr *hdr_tcp;
	bool success = true;

	/* Prepare */
	if (init_tuple4(&tuple4, "5.6.7.8", 5678, "192.0.2.128", 8765, L4PROTO_TCP))
		return false;
	/* The session entry that is supposed to be created in "tcp_close_state_handle". */
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434,
			"192.0.2.128", 8765, "5.6.7.8", 5678, V4_INIT);
	if (!session)
		return false;

	if (create_skb4_tcp(&tuple4, &skb, 100, 32))
		return false;
	if (pkt_init_ipv4(&pkt, skb))
		return false;
	hdr_tcp = tcp_hdr(skb);
	hdr_tcp->syn = true;
	hdr_tcp->rst = false;
	hdr_tcp->fin = false;

	/* Evaluate */
	success &= ASSERT_INT(VERDICT_STOLEN, tcp_closed_state(&pkt, &tuple4), "V4 syn-result");

	/* Validate */
	success &= ASSERT_INT(-ESRCH, sessiondb_get(&tuple4, NULL, &tmp), "V4 syn-session.");
	success &= ASSERT_INT(0, pktqueue_remove(session), "V4 syn pktqueue send");
	if (success)
		success &= ASSERT_UINT(V4_INIT, session->state, "V4 syn-state");

	session_return(session);
	/* kfree_skb(skb); "skb" kfreed when pktqueue is executed */
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

	if (init_tuple6(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_TCP))
		return false;
	if (init_tuple4(&tuple4, "0.0.0.4", 3434, "192.0.2.128", 1024, L4PROTO_TCP))
		return false;

	/* V6 SYN */
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
	char *prefixes4[] = { "192.0.2.2/32" };

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
//
//	/* UDP */
//	INIT_CALL_END(init(), test_udp(), end(), "UDP");
//
//	/* ICMP */
//	INIT_CALL_END(init(), test_icmp(), end(), "ICMP");
//
//	/* TCP */
//	INIT_CALL_END(init(), test_tcp_closed_state_handle_6(), end(), "TCP-CLOSED-6");
//	INIT_CALL_END(init(), test_tcp_closed_state_handle_4(), end(), "TCP-CLOSED-4");
//	INIT_CALL_END(init(), test_tcp(), end(), "test_tcp");

	END_TESTS;
}

static void filtering_test_exit(void)
{
	/* No code. */
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
