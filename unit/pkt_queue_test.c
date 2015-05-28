#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dhernandez");
MODULE_DESCRIPTION("Unit tests for the Packet queue module");
MODULE_ALIAS("nat64_test_pkt_queue");

#include "nat64/unit/session.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "session/pkt_queue.c"

/**
 * "asr" means add, send, remove
 */
static bool test_pkt_queue_asr(void)
{
	struct session_entry *session;
	struct packet pkt;
	struct sk_buff *skb;
	struct tuple tuple4;
	struct tcphdr *hdr_tcp;
	bool success = true;

	/* Prepare */
	if (is_error(init_tuple4(&tuple4, "5.6.7.8", 5678, "192.168.2.1", 8765, L4PROTO_TCP)))
		return false;
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "192.168.2.1", 8765, "5.6.7.8", 5678,
			V4_INIT); /* The session entry that is supposed to be created in "tcp_close_state_handle". */
	if (!session)
		return false;

	if (is_error(create_skb4_tcp(&tuple4, &skb, 100, 32)))
		goto fail;
	if (is_error(pkt_init_ipv4(&pkt, skb)))
		goto fail;
	hdr_tcp = tcp_hdr(skb);
	hdr_tcp->syn = true;
	hdr_tcp->rst = false;
	hdr_tcp->fin = false;

	/* Test */
	success &= ASSERT_INT(0, pktqueue_add(session, &pkt), "pktqueue_add 1");
	success &= ASSERT_INT(0, pktqueue_send(session), "pktqueue_send 1");
	success &= ASSERT_INT(1, icmp64_pop(), "pktqueue sent an icmp error");
	success &= ASSERT_INT(-ESRCH, pktqueue_remove(session), "pktqueue_remove 1");


	session_return(session);
	/* kfree_skb(skb); "skb" kfreed when pktqueue_send is executed */
	return success;

fail:
	session_return(session);
	return false;
}

/**
 * "ars" means add, remove, send
 */
static bool test_pkt_queue_ars(void)
{
	struct session_entry *session;
	struct packet pkt;
	struct sk_buff *skb;
	struct tuple tuple4;
	struct tcphdr *hdr_tcp;
	bool success = true;

	/* Prepare */
	if (is_error(init_tuple4(&tuple4, "5.6.7.8", 5678, "192.168.2.1", 8765, L4PROTO_TCP)))
		return false;
	session = session_create_str_tcp("1::2", 1212, "3::4", 3434, "192.168.2.1", 8765, "5.6.7.8", 5678,
			V4_INIT); /* The session entry that is supposed to be created in "tcp_close_state_handle". */
	if (!session)
		return false;

	if (is_error(create_skb4_tcp(&tuple4, &skb, 100, 32)))
		goto fail;
	if (is_error(pkt_init_ipv4(&pkt, skb)))
		goto fail;

	hdr_tcp = tcp_hdr(skb);
	hdr_tcp->syn = true;
	hdr_tcp->rst = false;
	hdr_tcp->fin = false;

	success &= ASSERT_INT(0, pktqueue_add(session, &pkt), "pktqueue_add 1");
	success &= ASSERT_INT(0, pktqueue_remove(session), "pktqueue_remove 1");
	success &= ASSERT_INT(-ESRCH, pktqueue_send(session), "pktqueue_send 1");
	success &= ASSERT_INT(0, icmp64_pop(), "pktqueue not sent an icmp error");


	session_return(session);
	/* kfree_skb(skb); "skb" kfreed when pktqueue_remove is executed */
	return success;

fail:
	session_return(session);
	return false;
}

static int pktqueue_test_init(void)
{
	START_TESTS("Packet queue");

	INIT_CALL_END(init_full(), test_pkt_queue_asr(), end_full(), "test_pkt_queue 1");
	INIT_CALL_END(init_full(), test_pkt_queue_ars(), end_full(), "test_pkt_queue 2");

	END_TESTS;
}

static void pktqueue_test_exit(void)
{
	/* No code. */
}

module_init(pktqueue_test_init);
module_exit(pktqueue_test_exit);
