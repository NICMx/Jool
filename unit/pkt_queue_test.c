#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/printk.h> /* pr_* */
#include <linux/ipv6.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dhernandez");
MODULE_DESCRIPTION("Unit tests for the Packet queue module");
MODULE_ALIAS("nat64_test_pkt_queue");

#include "nat64/comm/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/mod/icmp_wrapper.h"
#include "pkt_queue.c"

static struct session_entry *create_tcp_session(
		unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum tcp_state state)
{
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct session_entry *session;

	if (is_error(str_to_addr6(remote6_addr, &pair6.remote.address)))
		return NULL;
	pair6.remote.l4_id = remote6_id;
	if (is_error(str_to_addr6(local6_addr, &pair6.local.address)))
		return NULL;
	pair6.local.l4_id = local6_id;

	if (is_error(str_to_addr4(local4_addr, &pair4.local.address)))
		return NULL;
	pair4.local.l4_id = local4_id;
	if (is_error(str_to_addr4(remote4_addr, &pair4.remote.address)))
		return NULL;
	pair4.remote.l4_id = remote4_id;

	session = session_create(&pair4, &pair6, L4PROTO_TCP, NULL);
	session->state = state;
	return session;
}

static bool init(void)
{
	int error;

	error = pktqueue_init();
	if (error)
		goto fail;
	error = sessiondb_init();
	if (error)
		goto fail;

	return true;

fail:
	return false;
}

static void end(void)
{
	sessiondb_destroy();
	pktqueue_destroy();
}

/**
 * "asr" means add, send, remove
 */
static bool test_pkt_queue_asr(void)
{
	struct session_entry *session;
	struct tuple tuple;
	struct sk_buff *skb;
	struct ipv4_pair pair4;
	struct tcphdr *hdr_tcp;
	bool success = true;

	/* Prepare */
	if (is_error(init_pair4(&pair4, "5.6.7.8", 5678, "192.168.2.1", 8765)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_TCP)))
		return false;
	session = create_tcp_session("1::2", 1212, "3::4", 3434, "192.168.2.1", 8765, "5.6.7.8", 5678,
			V4_INIT); /* The session entry that is supposed to be created in "tcp_close_state_handle". */
	if (!session)
		return false;

	if (is_error(create_skb_ipv4_tcp(&pair4, &skb, 100))) {
		session_return(session);
		return false;
	}
	hdr_tcp = tcp_hdr(skb);
	hdr_tcp->syn = true;
	hdr_tcp->rst = false;
	hdr_tcp->fin = false;

	/* Test */
	success &= assert_equals_int(0, pktqueue_add(session, skb), "pktqueue_add 1");
	success &= assert_equals_int(0, pktqueue_send(session), "pktqueue_send 1");
	success &= assert_equals_int(1, icmp64_pop(), "pktqueue sent an icmp error");
	success &= assert_equals_int(-ENOENT, pktqueue_remove(session), "pktqueue_remove 1");


	session_return(session);
	/* kfree_skb(skb); "skb" kfreed when pktqueue_send is executed */
	return success;
}

/**
 * "ars" means add, remove, send
 */
static bool test_pkt_queue_ars(void)
{
	struct session_entry *session;
	struct tuple tuple;
	struct sk_buff *skb;
	struct ipv4_pair pair4;
	struct tcphdr *hdr_tcp;
	bool success = true;

	/* Prepare */
	if (is_error(init_pair4(&pair4, "5.6.7.8", 5678, "192.168.2.1", 8765)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_TCP)))
		return false;
	session = create_tcp_session("1::2", 1212, "3::4", 3434, "192.168.2.1", 8765, "5.6.7.8", 5678,
			V4_INIT); /* The session entry that is supposed to be created in "tcp_close_state_handle". */
	if (!session)
		return false;

	if (is_error(create_skb_ipv4_tcp(&pair4, &skb, 100))) {
		session_return(session);
		return false;
	}
	hdr_tcp = tcp_hdr(skb);
	hdr_tcp->syn = true;
	hdr_tcp->rst = false;
	hdr_tcp->fin = false;

	success &= assert_equals_int(0, pktqueue_add(session, skb), "pktqueue_add 1");
	success &= assert_equals_int(0, pktqueue_remove(session), "pktqueue_remove 1");
	success &= assert_equals_int(-ENOENT, pktqueue_send(session), "pktqueue_send 1");
	success &= assert_equals_int(0, icmp64_pop(), "pktqueue not sent an icmp error");


	session_return(session);
	/* kfree_skb(skb); "skb" kfreed when pktqueue_remove is executed */
	return success;
}

static int pktqueue_test_init(void)
{
	START_TESTS("Packet queue");

	INIT_CALL_END(init(), test_pkt_queue_asr(), end(), "test_pkt_queue 1");
	INIT_CALL_END(init(), test_pkt_queue_ars(), end(), "test_pkt_queue 2");

	END_TESTS;
}

static void pktqueue_test_exit(void)
{
	/* No code. */
}

module_init(pktqueue_test_init);
module_exit(pktqueue_test_exit);
