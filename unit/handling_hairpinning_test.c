#include <linux/module.h>
#include <linux/printk.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/bib.h"
#include "nat64/unit/session.h"
#include "nat64/unit/send_packet.h"
#include "nat64/unit/types.h"

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/pkt_queue.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/bib_db.h"
#include "nat64/mod/stateful/session_db.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/common/rfc6145/core.h"
#include "nat64/mod/common/core.h"

/**
 * There's a IPv6 network and the IPv4 Internet. The admin places a NAT64 in-between using the
 * following configuration.
 */
#define NAT64_POOL4 "192.0.2.128"
#define NAT64_POOL6 "3::"

/*
 * The IPv6 network has a HTTP service on address 1::1. The administrator publishes the service.
 * Now IPv4 nodes can browse through 1::1's webpages thinking its real address is 192.0.2.2.
 */
#define SERVER_ADDR6 "1::1"
#define SERVER_PORT6 80

/*
 * Somebody from the IPv4 side informs IPv6 node 1::2 about the service.
 * Now 1::2 thinks 1::1's address is 64:ff9b::192.0.2.2 and makes a request.
 */

#define SERVER_HAIRPIN_ADDR (NAT64_POOL6 NAT64_POOL4)

#define CLIENT_ADDR "1::2"
#define CLIENT_PORT 2048 /* random */

#define DYNAMIC_BIB_IPV4_PORT 1024 /* random; same port and range as CLIENT_PORT */

/*
 * The NAT64 will realize the destination address is its own, so it will bounce the packet back
 * using the correct address.
 */

static bool send(struct sk_buff *skb_in)
{
	return assert_equals_int(NF_STOLEN, core_6to4(skb_in), "Function result");
}

static bool test_hairpin(l4_protocol l4_proto, skb_creator create_skb_fn)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct sk_buff *skb_tmp = NULL;
	struct bib_entry *static_bib = NULL;
	struct bib_entry *dynamic_bib = NULL;
	struct session_entry *static_session = NULL;
	struct session_entry *dynamic_session = NULL;
	struct tuple tuple6;
	bool success = true;

	static_bib = bib_create_str(SERVER_ADDR6, SERVER_PORT6,
			NAT64_POOL4, SERVER_PORT6,
			l4_proto);
	dynamic_bib = bib_create_str(CLIENT_ADDR, CLIENT_PORT,
			NAT64_POOL4, DYNAMIC_BIB_IPV4_PORT,
			l4_proto);
	static_session = session_create_str(
			SERVER_ADDR6, SERVER_PORT6,
			SERVER_HAIRPIN_ADDR, DYNAMIC_BIB_IPV4_PORT,
			NAT64_POOL4, SERVER_PORT6,
			NAT64_POOL4, DYNAMIC_BIB_IPV4_PORT,
			l4_proto);
	dynamic_session = session_create_str(CLIENT_ADDR, CLIENT_PORT,
			SERVER_HAIRPIN_ADDR, SERVER_PORT6,
			NAT64_POOL4, DYNAMIC_BIB_IPV4_PORT,
			NAT64_POOL4, SERVER_PORT6,
			l4_proto);

	if (!static_bib || !dynamic_bib || !static_session || !dynamic_session)
		goto fail;

	/* Send the request. */
	if (is_error(init_ipv6_tuple(&tuple6,
			CLIENT_ADDR, CLIENT_PORT,
			SERVER_HAIRPIN_ADDR, SERVER_PORT6,
			l4_proto)))
		goto fail;
	if (is_error(create_skb_fn(&tuple6, &skb_in, 40, 32)))
		goto fail;

	success &= send(skb_in);
	success &= BIB_ASSERT(l4_proto, static_bib, dynamic_bib);
	success &= SESSION_ASSERT(l4_proto, static_session, dynamic_session);

	skb_out = skb_tmp = get_sent_skb();
	success &= assert_not_null(skb_out, "Request packet");
	if (!success)
		goto fail;

	do {
		success &= assert_equals_ipv6_str(SERVER_HAIRPIN_ADDR, &ipv6_hdr(skb_tmp)->saddr, "out src");
		success &= assert_equals_ipv6_str(SERVER_ADDR6, &ipv6_hdr(skb_tmp)->daddr, "out dst");
		skb_tmp = skb_tmp->next;
	} while (skb_tmp);
	switch (l4_proto) {
	case L4PROTO_UDP:
		success &= ASSERT_UINT(DYNAMIC_BIB_IPV4_PORT,
				be16_to_cpu(udp_hdr(skb_out)->source),
				"out's src port");
		success &= ASSERT_UINT(SERVER_PORT6,
				be16_to_cpu(udp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_TCP:
		success &= ASSERT_UINT(DYNAMIC_BIB_IPV4_PORT,
				be16_to_cpu(tcp_hdr(skb_out)->source),
				"out's src port");
		success &= ASSERT_UINT(SERVER_PORT6,
				be16_to_cpu(tcp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_ICMP:
	case L4PROTO_OTHER:
		log_err("Test is not designed for protocol %d.", l4_proto);
		success = false;
		break;
	}

	if (!success)
		goto fail;

	kfree_skb(skb_out);

	/* Send the response. */
	if (is_error(init_ipv6_tuple(&tuple6,
			SERVER_ADDR6, SERVER_PORT6,
			SERVER_HAIRPIN_ADDR, DYNAMIC_BIB_IPV4_PORT,
			l4_proto)))
		goto fail;
	if (is_error(create_skb_fn(&tuple6, &skb_in, 100, 32)))
		goto fail;

	success &= send(skb_in);
	/* The module should have reused the entries, so the database shouldn't have changed. */
	success &= BIB_ASSERT(l4_proto, static_bib, dynamic_bib);
	success &= SESSION_ASSERT(l4_proto, static_session, dynamic_session);

	skb_out = skb_tmp = get_sent_skb();
	success &= assert_not_null(skb_out, "Response packet");
	if (!success)
		goto fail;

	do {
		success &= assert_equals_ipv6_str(SERVER_HAIRPIN_ADDR, &ipv6_hdr(skb_out)->saddr, "out src");
		success &= assert_equals_ipv6_str(CLIENT_ADDR, &ipv6_hdr(skb_out)->daddr, "out dst");
		skb_tmp = skb_tmp->next;
	} while (skb_tmp);
	switch (l4_proto) {
	case L4PROTO_UDP:
		success &= ASSERT_UINT(SERVER_PORT6,
				be16_to_cpu(udp_hdr(skb_out)->source),
				"out's src port");
		success &= ASSERT_UINT(CLIENT_PORT,
				be16_to_cpu(udp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_TCP:
		success &= ASSERT_UINT(SERVER_PORT6,
				be16_to_cpu(tcp_hdr(skb_out)->source),
				"out's src port");
		success &= ASSERT_UINT(CLIENT_PORT,
				be16_to_cpu(tcp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_ICMP:
	case L4PROTO_OTHER:
		log_err("Test is not designed for protocol %d.", l4_proto);
		success = false;
		break;
	}

	kfree_skb(skb_out);
	session_return(dynamic_session);
	session_return(static_session);
	bib_kfree(dynamic_bib);
	bib_kfree(static_bib);
	return success;

fail:
	kfree_skb(skb_out);
	if (dynamic_session)
		session_return(dynamic_session);
	if (static_session)
		session_return(static_session);
	if (dynamic_bib)
		bib_kfree(dynamic_bib);
	if (static_bib)
		bib_kfree(static_bib);

	return false;
}

static bool test_icmp(void)
{
	struct tuple tuple6;
	struct sk_buff *skb;
	bool success = true;

	if (is_error(init_ipv6_tuple(&tuple6,
			CLIENT_ADDR, CLIENT_PORT,
			SERVER_HAIRPIN_ADDR, SERVER_PORT6,
			L4PROTO_ICMP)))
		return false;
	if (is_error(create_skb6_icmp_info(&tuple6, &skb, 100, 32)))
		return false;
	set_sent_skb(NULL);

	success &= assert_equals_int(NF_DROP, core_6to4(skb), "Request result");
	success &= assert_null(get_sent_skb(), "Sent SKB");

	return success;
}

static void deinit(void)
{
	end_full();
	fragdb_destroy();
}

static bool init(void)
{
	if (is_error(fragdb_init()))
		goto fragdb_fail;
	if (!init_full())
		goto initfull_fail;

	if (!bib_inject_str(SERVER_ADDR6, SERVER_PORT6, NAT64_POOL4, SERVER_PORT6, L4PROTO_UDP))
		goto inject_fail;
	if (!bib_inject_str(SERVER_ADDR6, SERVER_PORT6, NAT64_POOL4, SERVER_PORT6, L4PROTO_TCP))
		goto inject_fail;
	if (!bib_inject_str(SERVER_ADDR6, SERVER_PORT6, NAT64_POOL4, SERVER_PORT6, L4PROTO_ICMP))
		goto inject_fail;

	return true;

inject_fail:
	end_full();
initfull_fail:
	fragdb_destroy();
fragdb_fail:
	return false;
}

static int init_test_module(void)
{
	START_TESTS("Handling Hairpinning");

	if (!init())
		return -EINVAL;

	/*
	 * Well, the only thing not being tested here, I think, is hairpinning not getting in the way
	 * when there's no need for it.
	 * But that's handled in every other test, ever.
	 */

	CALL_TEST(test_hairpin(L4PROTO_UDP, create_skb6_udp), "UDP");
	CALL_TEST(test_hairpin(L4PROTO_TCP, create_skb6_tcp), "TCP");
	CALL_TEST(test_icmp(), "ICMP");

	deinit();

	END_TESTS;
}

static void cleanup_test_module(void)
{
	/* No code. */
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Handling Hairpinning module test.");
module_init(init_test_module);
module_exit(cleanup_test_module);
