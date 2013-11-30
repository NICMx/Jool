#include <linux/module.h>
#include <linux/printk.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/bib_session_helper.h"
#include "nat64/unit/send_packet_impersonator.h"

#include "nat64/comm/str_utils.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"
#include "nat64/mod/config.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/core.h"


/**
 * There's a IPv6 network and the IPv4 Internet. The admin places a NAT64 in-between using the
 * following configuration.
 */
#define NAT64_IPV4_ADDR "2.2.2.2"
#define NAT64_IPV6_POOL "3::"
#define NAT64_IPV6_ADDR "3::3"

/*
 * The IPv6 network has a HTTP service on address 4::4. The administrator publishes the service.
 * Now IPv4 nodes can browse through 4::4's webpages thinking its real address is 2.2.2.2.
 */
#define SERVER_ADDR "4::4"
#define SERVER_PORT 80
#define SERVER_HAIRPIN_ADDR (NAT64_IPV6_POOL NAT64_IPV4_ADDR)

#define STATIC_BIB_IPV6_ADDR SERVER_ADDR
#define STATIC_BIB_IPV6_PORT SERVER_PORT
#define STATIC_BIB_IPV4_ADDR NAT64_IPV4_ADDR
#define STATIC_BIB_IPV4_PORT STATIC_BIB_IPV6_PORT

/*
 * Somebody from the IPv4 side informs IPv6 node 4::5 about the service.
 * Now 4::5 thinks 4::4's address is 3::2.2.2.2 and makes a request.
 */
#define CLIENT_ADDR		"4::5"
#define CLIENT_PORT		2048 /* random */

#define DYNAMIC_BIB_IPV6_ADDR		CLIENT_ADDR
#define DYNAMIC_BIB_IPV6_PORT		CLIENT_PORT
#define DYNAMIC_BIB_IPV4_ADDR		NAT64_IPV4_ADDR
#define DYNAMIC_BIB_IPV4_PORT		1024 /* random; same port and range as DYNAMIC_BIB_IPV6_PORT */

#define DYNAMIC_SESSION_IPV6_REMOTE_ADDR	DYNAMIC_BIB_IPV6_ADDR
#define DYNAMIC_SESSION_IPV6_REMOTE_PORT	DYNAMIC_BIB_IPV6_PORT
#define DYNAMIC_SESSION_IPV6_LOCAL_ADDR		SERVER_HAIRPIN_ADDR
#define DYNAMIC_SESSION_IPV6_LOCAL_PORT		STATIC_BIB_IPV6_PORT
#define DYNAMIC_SESSION_IPV4_LOCAL_ADDR		DYNAMIC_BIB_IPV4_ADDR
#define DYNAMIC_SESSION_IPV4_LOCAL_PORT		DYNAMIC_BIB_IPV4_PORT
#define DYNAMIC_SESSION_IPV4_REMOTE_ADDR	NAT64_IPV4_ADDR
#define DYNAMIC_SESSION_IPV4_REMOTE_PORT	DYNAMIC_SESSION_IPV6_LOCAL_PORT

/*
 * The NAT64 realizes the destination address is its own, so it bounces the packet back using the
 * correct address.
 */
#define STATIC_SESSION_IPV4_REMOTE_ADDR DYNAMIC_SESSION_IPV4_LOCAL_ADDR
#define STATIC_SESSION_IPV4_REMOTE_PORT DYNAMIC_SESSION_IPV4_LOCAL_PORT
#define STATIC_SESSION_IPV4_LOCAL_ADDR DYNAMIC_SESSION_IPV4_REMOTE_ADDR
#define STATIC_SESSION_IPV4_LOCAL_PORT DYNAMIC_SESSION_IPV4_REMOTE_PORT
#define STATIC_SESSION_IPV6_LOCAL_ADDR (NAT64_IPV6_POOL STATIC_SESSION_IPV4_REMOTE_ADDR)
#define STATIC_SESSION_IPV6_LOCAL_PORT DYNAMIC_SESSION_IPV4_LOCAL_PORT
#define STATIC_SESSION_IPV6_REMOTE_ADDR STATIC_BIB_IPV6_ADDR
#define STATIC_SESSION_IPV6_REMOTE_PORT STATIC_BIB_IPV6_PORT


static struct session_entry *create_dynamic_session(int l4_proto)
{
	struct session_entry *session;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;

	if (str_to_addr6(DYNAMIC_SESSION_IPV6_REMOTE_ADDR, &pair6.remote.address) != 0)
		return NULL;
	if (str_to_addr6(DYNAMIC_SESSION_IPV6_LOCAL_ADDR, &pair6.local.address) != 0)
		return NULL;
	if (str_to_addr4(DYNAMIC_SESSION_IPV4_LOCAL_ADDR, &pair4.local.address) != 0)
		return NULL;
	if (str_to_addr4(DYNAMIC_SESSION_IPV4_REMOTE_ADDR, &pair4.remote.address) != 0)
		return NULL;
	pair6.remote.l4_id = DYNAMIC_SESSION_IPV6_REMOTE_PORT;
	pair6.local.l4_id = DYNAMIC_SESSION_IPV6_LOCAL_PORT;
	pair4.local.l4_id = DYNAMIC_SESSION_IPV4_LOCAL_PORT;
	pair4.remote.l4_id = DYNAMIC_SESSION_IPV4_REMOTE_PORT;

	session = session_create(&pair4, &pair6, l4_proto);
	if (!session) {
		log_warning("Could not allocate the dynamic session entry.");
		return NULL;
	}

	return session;
}

static struct session_entry *create_static_session(int l4_proto)
{
	struct session_entry *session;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;

	if (str_to_addr4(STATIC_SESSION_IPV4_REMOTE_ADDR, &pair4.remote.address) != 0)
		return NULL;
	if (str_to_addr4(STATIC_SESSION_IPV4_LOCAL_ADDR, &pair4.local.address) != 0)
		return NULL;
	if (str_to_addr6(STATIC_SESSION_IPV6_LOCAL_ADDR, &pair6.local.address) != 0)
		return NULL;
	if (str_to_addr6(STATIC_SESSION_IPV6_REMOTE_ADDR, &pair6.remote.address) != 0)
		return NULL;
	pair4.remote.l4_id = STATIC_SESSION_IPV4_REMOTE_PORT;
	pair4.local.l4_id = STATIC_SESSION_IPV4_LOCAL_PORT;
	pair6.local.l4_id = STATIC_SESSION_IPV6_LOCAL_PORT;
	pair6.remote.l4_id = STATIC_SESSION_IPV6_REMOTE_PORT;

	session = session_create(&pair4, &pair6, l4_proto);
	if (!session) {
		log_warning("Could not allocate the static session entry.");
		return NULL;
	}

	return session;
}

static struct bib_entry *create_and_insert_static_bib(int l4_proto)
{
	struct bib_entry *bib;
	struct ipv4_tuple_address addr4;
	struct ipv6_tuple_address addr6;

	if (str_to_addr4(STATIC_BIB_IPV4_ADDR, &addr4.address) != 0)
		return NULL;
	if (str_to_addr6(STATIC_BIB_IPV6_ADDR, &addr6.address) != 0)
		return NULL;
	addr4.l4_id = STATIC_BIB_IPV4_PORT;
	addr6.l4_id = STATIC_BIB_IPV6_PORT;

	bib = bib_create(&addr4, &addr6, true);
	if (!bib) {
		log_warning("Could not allocate the static BIB entry.");
		return NULL;
	}
	if (bib_add(bib, l4_proto) != 0)
		return NULL;

	return bib;
}

static int strs_to_pair6(char *src_addr, u16 src_port, char *dst_addr, u16 dst_port, struct ipv6_pair *pair6)
{
	int error;

	error = str_to_addr6(src_addr, &pair6->remote.address);
	if (error) {
		log_warning("Cannot parse %pI6c as a IPv6 address.", src_addr);
		return error;
	}
	error = str_to_addr6(dst_addr, &pair6->local.address);
	if (error) {
		log_warning("Cannot parse %pI6c as a IPv6 address.", dst_addr);
		return error;
	}
	pair6->remote.l4_id = src_port;
	pair6->local.l4_id = dst_port;

	return 0;
}

/*
static int strs_to_pair4(char *src_addr, u16 src_port, char *dst_addr, u16 dst_port, struct ipv4_pair *pair4)
{
	int error;

	error = str_to_addr4(src_addr, &pair4->remote.address);
	if (error) {
		log_warning("Cannot parse %pI4 as a IPv4 address.", src_addr);
		return error;
	}
	error = str_to_addr4(dst_addr, &pair4->local.address);
	if (error) {
		log_warning("Cannot parse %pI4 as a IPv4 address.", dst_addr);
		return error;
	}
	pair4->remote.l4_id = src_port;
	pair4->local.l4_id = dst_port;

	return 0;
}
*/

static struct bib_entry *create_dynamic_bib(int l4_proto)
{
	struct bib_entry *bib;
	struct ipv6_tuple_address addr6;
	struct ipv4_tuple_address addr4;

	if (str_to_addr6(DYNAMIC_BIB_IPV6_ADDR, &addr6.address) != 0)
		return NULL;
	if (str_to_addr4(DYNAMIC_BIB_IPV4_ADDR, &addr4.address) != 0)
		return NULL;
	addr6.l4_id = DYNAMIC_BIB_IPV6_PORT;
	addr4.l4_id = DYNAMIC_BIB_IPV4_PORT;

	bib = bib_create(&addr4, &addr6, true);
	if (!bib) {
		log_warning("Could not allocate the dynamic BIB entry.");
		return NULL;
	}

	return bib;
}

static bool test_hairpin(l4_protocol l4_proto,
		int (*create_skb_cb)(struct ipv6_pair *, struct sk_buff **, u16))
{
	struct sk_buff *skb_in, *skb_out;
	struct bib_entry *static_bib, *dynamic_bib;
	struct session_entry *static_session, *dynamic_session;
	struct ipv6_pair pair6_request, pair6_response;
	int error;
	bool success = true;

	/* TODO (test) free stuff on failure. */
	static_bib = create_and_insert_static_bib(l4_proto);
	if (!static_bib)
		return false;
	dynamic_bib = create_dynamic_bib(l4_proto);
	if (!dynamic_bib)
		return false;
	static_session = create_static_session(l4_proto);
	if (!static_session)
		return false;
	dynamic_session = create_dynamic_session(l4_proto);
	if (!dynamic_session)
		return false;

	error = strs_to_pair6(CLIENT_ADDR, CLIENT_PORT, SERVER_HAIRPIN_ADDR, SERVER_PORT, &pair6_request);
	if (error)
		return false;
	error = strs_to_pair6(SERVER_ADDR, SERVER_PORT, STATIC_SESSION_IPV6_LOCAL_ADDR,
			STATIC_SESSION_IPV6_LOCAL_PORT, &pair6_response);
	if (error)
		return false;

	/* Send the request. */
	if (create_skb_cb(&pair6_request, &skb_in, 100) != 0)
		return false;

	success &= assert_equals_int(NF_STOLEN, core_6to4(skb_in), "Request result");
	success &= BIB_ASSERT(l4_proto, static_bib, dynamic_bib);
	success &= SESSION_ASSERT(l4_proto, static_session, dynamic_session);
	skb_out = get_sent_skb();

	success &= assert_not_null(skb_out, "Request packet");
	success &= assert_equals_ipv6_str(STATIC_SESSION_IPV6_LOCAL_ADDR, &ipv6_hdr(skb_out)->saddr,
			"out's src addr");
	success &= assert_equals_ipv6_str(SERVER_ADDR, &ipv6_hdr(skb_out)->daddr, "out's dst addr");
	switch (l4_proto) {
	case L4PROTO_UDP:
		success &= assert_equals_u16(STATIC_SESSION_IPV6_LOCAL_PORT,
				be16_to_cpu(udp_hdr(skb_out)->source),
				"out's src port");
		success &= assert_equals_u16(SERVER_PORT,
				be16_to_cpu(udp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_TCP:
		success &= assert_equals_u16(STATIC_SESSION_IPV6_LOCAL_PORT,
				be16_to_cpu(tcp_hdr(skb_out)->source),
				"out's src port");
		success &= assert_equals_u16(SERVER_PORT,
				be16_to_cpu(tcp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_ICMP:
	case L4PROTO_NONE:
		log_warning("Test is not designed for protocol %d.", l4_proto);
		success = false;
		break;
	}

	if (!success)
		return false;

	kfree_skb(skb_out);

	/* Send the response. */
	if (create_skb_cb(&pair6_response, &skb_in, 100) != 0)
		return false;
	success &= assert_equals_int(NF_STOLEN, core_6to4(skb_in), "Response result");
	/* The module should have reused the entries, so the database shouldn't have changed. */
	success &= BIB_ASSERT(l4_proto, static_bib, dynamic_bib);
	success &= SESSION_ASSERT(l4_proto, static_session, dynamic_session);
	skb_out = get_sent_skb();

	success &= assert_not_null(skb_out, "Response packet");
	success &= assert_equals_ipv6_str(SERVER_HAIRPIN_ADDR, &ipv6_hdr(skb_out)->saddr,
			"out's src addr");
	success &= assert_equals_ipv6_str(CLIENT_ADDR, &ipv6_hdr(skb_out)->daddr, "out's dst addr");
	switch (l4_proto) {
	case L4PROTO_UDP:
		success &= assert_equals_u16(SERVER_PORT,
				be16_to_cpu(udp_hdr(skb_out)->source),
				"out's src port");
		success &= assert_equals_u16(CLIENT_PORT,
				be16_to_cpu(udp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_TCP:
		success &= assert_equals_u16(SERVER_PORT,
				be16_to_cpu(tcp_hdr(skb_out)->source),
				"out's src port");
		success &= assert_equals_u16(CLIENT_PORT,
				be16_to_cpu(tcp_hdr(skb_out)->dest),
				"out's dst port");
		break;
	case L4PROTO_ICMP:
	case L4PROTO_NONE:
		log_warning("Test is not designed for protocol %d.", l4_proto);
		success = false;
		break;
	}

	if (!success)
		return false;

	kfree_skb(skb_out);

	/* We're done. */
	print_bibs(l4_proto);
	print_sessions(l4_proto);

	return success;
}

static void deinit(void)
{
	translate_packet_destroy();
	filtering_destroy();
	session_destroy();
	bib_destroy();
	pool4_destroy();
	pool6_destroy();
	pktmod_destroy();
}

static int init(void)
{
	char *pool6[] = { NAT64_IPV6_POOL "/96" };
	char *pool4[] = { NAT64_IPV4_ADDR };
	int error;

	error = pktmod_init();
	if (error)
		goto failure;
	error = pool6_init(pool6, ARRAY_SIZE(pool6));
	if (error)
		goto failure;
	error = pool4_init(pool4, ARRAY_SIZE(pool4));
	if (error)
		goto failure;
	error = bib_init();
	if (error)
		goto failure;
	error = session_init();
	if (error)
		goto failure;
	error = filtering_init();
	if (error)
		goto failure;
	error = translate_packet_init();
	if (error)
		goto failure;

	return 0;

failure:
	deinit();
	return error;
}

static int create_syn_skb(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	int error = create_skb_ipv6_tcp(pair6, result, payload_len);
	if (error)
		return error;

	tcp_hdr(*result)->syn = 1;
	return 0;
}

static int init_test_module(void)
{
	int error;
	START_TESTS("Handling Hairpinning");

	error = init();
	if (error)
		return error;

	/* TODO (test) test errors (eg. ICMP hairpins). */

	CALL_TEST(test_hairpin(L4PROTO_UDP, create_skb_ipv6_udp), "UDP");
	CALL_TEST(test_hairpin(L4PROTO_TCP, create_syn_skb), "TCP");

	/* CALL_TEST(test_hairpin(L4PROTO_UDP, create_packet_ipv6_udp_fragmented_disordered), "UDP"); */
	/* CALL_TEST(test_hairpin(L4PROTO_TCP, create_packet_ipv6_tcp_fragmented_disordered), "TCP"); */

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
