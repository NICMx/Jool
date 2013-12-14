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

#include "nat64/comm/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "filtering_and_updating.c"

static noinline bool str_to_addr6_verbose(const char *str, struct in6_addr *addr)
{
	if (is_error(str_to_addr6(str, addr))) {
		log_warning("Cannot parse '%s' as a valid IPv6 address", str);
		return false;
	}
	return true;
}

static noinline bool str_to_addr4_verbose(const char *str, struct in_addr *addr)
{
	if (is_error(str_to_addr4(str, addr))) {
		log_warning("Cannot parse '%s' as a valid IPv4 address", str);
		return false;
	}
	return true;
}

#define IPV6_EXTRACT_ADDR "64:ff9b::192.168.2.3"
#define IPV4_EXTRACTED_ADDR "192.168.2.3"
static noinline bool test_extract_ipv4_from_ipv6(void)
{
	struct in6_addr addr6;
	struct in_addr extracted4;
	bool success = true;

	if (is_error(pool6_init(NULL, 0)))
		return false;
	if (!str_to_addr6_verbose(IPV6_EXTRACT_ADDR, &addr6))
		return false;

	success &= assert_true(extract_ipv4(&addr6, &extracted4), "result");
	success &= assert_equals_ipv4_str(IPV4_EXTRACTED_ADDR, &extracted4, "address");

	pool6_destroy();
	return success;
}


#define IPV6_EMBEDDED_ADDR "64:ff9b::192.168.2.3"
#define IPV4_EMBEDDABLE_ADDR "192.168.2.3"
static noinline bool test_embed_ipv4_in_ipv6(void)
{
	struct in_addr embeddable4;
	struct in6_addr embed6;
	bool success = true;

	if (is_error(pool6_init(NULL, 9)))
		return false;
	if (!str_to_addr4_verbose(IPV4_EMBEDDABLE_ADDR, &embeddable4))
		return false;

	success &= assert_true(append_ipv4(&embeddable4, &embed6) , "result");
	success &= assert_equals_ipv6_str(IPV6_EMBEDDED_ADDR, &embed6, "address");

	return success;
}

#define IPV6_INJECT_BIB_ENTRY_SRC_ADDR "2001:db8:c0ca:1::1"
#define IPV6_INJECT_BIB_ENTRY_SRC_PORT 1080
#define IPV4_INJECT_BIB_ENTRY_DST_ADDR "192.168.2.1"
#define IPV4_INJECT_BIB_ENTRY_DST_PORT 1082
#define INIT_TUPLE_ICMP_ID 10
static noinline bool inject_bib_entry(u_int8_t l4protocol)
{
	struct ipv4_tuple_address ta_ipv4;
	struct ipv6_tuple_address ta_ipv6;
	struct in_addr addr4;
	struct in6_addr addr6;
	struct bib_entry *bib_e;

	if (!str_to_addr4_verbose(IPV4_INJECT_BIB_ENTRY_DST_ADDR, &addr4))
		return false;
	if (!str_to_addr6_verbose(IPV6_INJECT_BIB_ENTRY_SRC_ADDR, &addr6))
		return false;

	if (l4protocol == L4PROTO_ICMP) {
		transport_address_ipv4(addr4, INIT_TUPLE_ICMP_ID, &ta_ipv4);
		transport_address_ipv6(addr6, INIT_TUPLE_ICMP_ID, &ta_ipv6);
	} else {
		transport_address_ipv4(addr4, IPV4_INJECT_BIB_ENTRY_DST_PORT, &ta_ipv4);
		transport_address_ipv6(addr6, IPV6_INJECT_BIB_ENTRY_SRC_PORT, &ta_ipv6);
	}

	bib_e = bib_create(&ta_ipv4, &ta_ipv6, false);
	if (!bib_e) {
		log_warning("Could not allocate the BIB entry.");
		return false;
	}

	if (bib_add(bib_e, l4protocol) != 0) {
		log_warning("Could not insert the BIB entry to the table.");
		return false;
	}

	return true;
}

#define IPV4_ALLOCATED_ADDR     "192.168.2.1"
static noinline bool test_allocate_ipv4_transport_address(void)
{
	struct tuple tuple;
	struct ipv4_tuple_address tuple_addr;
	struct in_addr expected_addr;
	bool success = true;

	success &= str_to_addr4_verbose(IPV4_ALLOCATED_ADDR, &expected_addr);
	success &= inject_bib_entry(L4PROTO_ICMP);
	success &= inject_bib_entry(L4PROTO_TCP);
	success &= inject_bib_entry(L4PROTO_UDP);
	if (!success)
		return false;

	if (is_error(init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_ICMP)))
		return false;
	success &= assert_true(allocate_ipv4_transport_address(&tuple, &tuple_addr), "ICMP result");
	success &= assert_equals_ipv4(&expected_addr , &tuple_addr.address, "ICMP address");

	if (is_error(init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_TCP)))
		return false;
	success &= assert_true(allocate_ipv4_transport_address(&tuple, &tuple_addr), "TCP result");
	success &= assert_equals_ipv4(&expected_addr , &tuple_addr.address, "TCP address");
	success &= assert_true(tuple_addr.l4_id > 1023, "Port range for TCP");

	if (is_error(init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_UDP)))
		return false;
	success &= assert_true(allocate_ipv4_transport_address(&tuple, &tuple_addr), "UDP result");
	success &= assert_equals_ipv4(&expected_addr , &tuple_addr.address, "UDP address");
	success &= assert_true(tuple_addr.l4_id % 2 == 0, "UDP port parity");
	success &= assert_true(tuple_addr.l4_id > 1023, "UDP Port range");

	return success;
}


#define IPV4_ALLOCATED_PORT_DIGGER 1024
static noinline bool test_allocate_ipv4_transport_address_digger(void)
{
	struct in_addr expected_addr;
	struct tuple tuple;
	struct ipv4_tuple_address new_ipv4_transport_address;
	bool success = true;

	success &= inject_bib_entry(L4PROTO_ICMP);
	success &= inject_bib_entry(L4PROTO_TCP);
	if (is_error(init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_UDP)))
		return false;
	success &= str_to_addr4_verbose(IPV4_ALLOCATED_ADDR, &expected_addr);
	if (!success)
		return false;

	success &= assert_true(allocate_ipv4_transport_address_digger(&tuple, L4PROTO_UDP,
			&new_ipv4_transport_address),
			"Check that we can allocate a brand new IPv4 transport address for UDP.");
	success &= assert_equals_ipv4(&new_ipv4_transport_address.address, &expected_addr,
			"Check that the allocated IPv4 address is correct for UDP.");
	success &= assert_true(new_ipv4_transport_address.l4_id % 2 == 0,
			"Check that the allocated IPv4 port is even.");
	success &= assert_true(new_ipv4_transport_address.l4_id > 1023,
			"Check that the allocated IPv4 port is in the upper range.");

	return success;
}

static int bib_count_fn(struct bib_entry *bib, void *arg)
{
	int *count = arg;
	(*count)++;
	return 0;
}

static bool assert_bib_count(int expected, l4_protocol proto)
{
	int count = 0;
	bib_for_each(proto, bib_count_fn, &count);
	return assert_equals_int(expected, count, "BIB count");
}

static bool assert_bib_exists(unsigned char *addr6, u16 port6, unsigned char *addr4, u16 port4,
		l4_protocol proto, unsigned int session_count)
{
	struct bib_entry *bib;
	struct ipv6_tuple_address tuple_addr;
	bool success = true;

	if (!str_to_addr6_verbose(addr6, &tuple_addr.address))
		return false;
	tuple_addr.l4_id = port6;

	bib = bib_get_by_ipv6(&tuple_addr, proto);
	success &= assert_not_null(bib, "BIB exists");
	if (!success)
		return false;

	success &= assert_equals_ipv6_str(addr6, &bib->ipv6.address, "IPv6 address");
	success &= assert_equals_u16(port6, bib->ipv6.l4_id, "IPv6 port");
	success &= assert_equals_ipv4_str(addr4, &bib->ipv4.address, "IPv4 address");
	success &= assert_equals_u16(port4, bib->ipv4.l4_id, "IPv4 port");
	success &= assert_false(bib->is_static, "BIB is dynamic");
	success &= assert_list_count(session_count, &bib->sessions, "Session count");

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
	session_for_each(proto, session_count_fn, &count);
	return assert_equals_int(expected, count, "Session count");
}

static bool assert_session_exists(unsigned char *remote_addr6, u16 remote_port6,
		unsigned char *local_addr6, u16 local_port6,
		unsigned char *local_addr4, u16 local_port4,
		unsigned char *remote_addr4, u16 remote_port4,
		l4_protocol proto, u_int8_t state)
{
	struct session_entry *session;
	struct ipv6_pair pair6;
	bool success = true;

	if (!str_to_addr6_verbose(remote_addr6, &pair6.remote.address))
		return false;
	pair6.remote.l4_id = remote_port6;
	if (!str_to_addr6_verbose(local_addr6, &pair6.local.address))
		return false;
	pair6.local.l4_id = local_port6;

	session = session_get_by_ipv6(&pair6, proto);
	success &= assert_not_null(session, "Session exists");
	if (!success)
		return false;

	success &= assert_equals_ipv6_str(remote_addr6, &session->ipv6.remote.address, "remote addr6");
	success &= assert_equals_u16(remote_port6, session->ipv6.remote.l4_id, "remote port6");
	success &= assert_equals_ipv6_str(local_addr6, &session->ipv6.local.address, "local addr6");
	success &= assert_equals_u16(local_port6, session->ipv6.local.l4_id, "local port6");
	success &= assert_equals_ipv4_str(local_addr4, &session->ipv4.local.address, "local addr4");
	success &= assert_equals_u16(local_port4, session->ipv4.local.l4_id, "local port4");
	success &= assert_equals_ipv4_str(remote_addr4, &session->ipv4.remote.address, "remote addr4");
	success &= assert_equals_u16(remote_port4, session->ipv4.remote.l4_id, "remote port4");
	success &= assert_not_null(session->bib, "Session's BIB");
	success &= assert_equals_int(proto, session->l4_proto, "Session's l4 proto");
	success &= assert_equals_int(state, session->state, "Session's state");

	return success;
}

#define INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR "2001:db8:c0ca:1::1"
#define INIT_TUPLE_IPV6_HAIR_LOOP_SRC_ADDR "64:ff9b::192.168.2.44"
#define INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR "192.168.100.44"
static noinline bool test_filtering_and_updating(void)
{
	struct fragment *frag;
	struct sk_buff *skb;
	struct tuple tuple;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	bool success = true;

	/* ICMP errors should pass happily, but not affect the tables. */
	if (is_error(init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_ICMP)))
		return false;
	if (is_error(create_skb_ipv4_icmp_error(&pair4, &skb, 100)))
		return false;
	if (is_error(frag_create_from_skb(skb, &frag)))
		return false;

	icmp_hdr(skb)->type = ICMP_DEST_UNREACH;
	success &= assert_equals_int(VER_CONTINUE, filtering_and_updating(frag, &tuple), "ICMP error");
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	frag_kfree(frag);
	if (!success)
		return false;

	/* This step should get rid of hairpinning loops. */
	if (is_error(init_pair6(&pair6, "64:ff9b::1:2", 1212, "64:ff9b::3:4", 3434)))
		return false;
	if (is_error(init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb_ipv6_udp(&pair6, &skb, 100)))
		return false;
	if (is_error(frag_create_from_skb(skb, &frag)))
		return false;

	success &= assert_equals_int(VER_DROP, filtering_and_updating(frag, &tuple), "Hairpinning");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	frag_kfree(frag);
	if (!success)
		return false;

	/* Packets not belonging to the IPv6 must not be translated. */
	if (is_error(init_pair6(&pair6, "1::2", 1212, INIT_TUPLE_IPV6_HAIR_LOOP_DST_ADDR, 3434)))
		return false;
	if (is_error(init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb_ipv6_udp(&pair6, &skb, 100)))
		return false;
	if (is_error(frag_create_from_skb(skb, &frag)))
		return false;

	success &= assert_equals_int(VER_DROP, filtering_and_updating(frag, &tuple), "Not pool6 packet");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	frag_kfree(frag);
	if (!success)
		return false;

	/* Packets not belonging to the IPv4 must not be translated. */
	if (is_error(init_pair4(&pair4, INIT_TUPLE_IPV4_NOT_POOL_DST_ADDR, 8765, "5.6.7.8", 5678)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb_ipv4_udp(&pair4, &skb, 100)))
		return false;
	if (is_error(frag_create_from_skb(skb, &frag)))
		return false;

	success &= assert_equals_int(VER_DROP, filtering_and_updating(frag, &tuple), "Not pool4 packet");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	frag_kfree(frag);
	if (!success)
		return false;

	/* Other IPv6 packets should be processed normally. */
	if (is_error(init_pair6(&pair6, "1::2", 1212, "64:ff9b::3:4", 3434)))
		return false;
	if (is_error(init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb_ipv6_udp(&pair6, &skb, 100)))
		return false;
	if (is_error(frag_create_from_skb(skb, &frag)))
		return false;

	success &= assert_equals_int(VER_CONTINUE, filtering_and_updating(frag, &tuple), "IPv6 success");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_session_count(1, L4PROTO_UDP);

	frag_kfree(frag);
	if (!success)
		return false;

	/* Other IPv4 packets should be processed normally. */
	if (is_error(init_pair4(&pair4, "0.3.0.4", 3434, "192.168.2.1", 1024)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple, &pair4, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb_ipv4_udp(&pair4, &skb, 100)))
		return false;
	if (is_error(frag_create_from_skb(skb, &frag)))
		return false;

	success &= assert_equals_int(VER_CONTINUE, filtering_and_updating(frag, &tuple), "IPv4 success");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_session_count(1, L4PROTO_UDP);

	frag_kfree(frag);
	if (!success)
		return false;

	return success;
}

static noinline bool test_udp(void)
{
	struct fragment *frag6, *frag4;
	struct sk_buff *skb6, *skb4;
	struct tuple tuple6, tuple4;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	bool success = true;

	/* Prepare the IPv6 packet. */
	if (is_error(init_pair6(&pair6, "1::2", 1212, "3::4", 3434)))
		return false;
	if (is_error(init_ipv6_tuple_from_pair(&tuple6, &pair6, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb_ipv6_udp(&pair6, &skb6, 16)))
		return false;
	if (is_error(frag_create_from_skb(skb6, &frag6)))
		return false;

	/* Prepare the IPv4 packet. */
	if (is_error(init_pair4(&pair4, "0.0.0.4", 3434, "192.168.2.1", 1024)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple4, &pair4, L4PROTO_UDP)))
		return false;
	if (is_error(create_skb_ipv4_udp(&pair4, &skb4, 16)))
		return false;
	if (is_error(frag_create_from_skb(skb4, &frag4)))
		return false;

	/* A IPv4 packet attempts to be translated without state */
	success &= assert_equals_int(VER_DROP, ipv4_udp(frag4, &tuple4), "result");
	success &= assert_bib_count(0, L4PROTO_UDP);
	success &= assert_session_count(0, L4PROTO_UDP);

	/* IPv6 packet and gets translated correctly. */
	success &= assert_equals_int(VER_CONTINUE, ipv6_udp(frag6, &tuple6), "result");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_UDP, 1);
	success &= assert_session_count(1, L4PROTO_UDP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.168.2.1", 1024, "0.0.0.4", 3434,
			L4PROTO_UDP, 0);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	success &= assert_equals_int(VER_CONTINUE, ipv4_udp(frag4, &tuple4), "result");
	success &= assert_bib_count(1, L4PROTO_UDP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_UDP, 1);
	success &= assert_session_count(1, L4PROTO_UDP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.168.2.1", 1024, "0.0.0.4", 3434,
			L4PROTO_UDP, 0);

	/* Quit */
	frag_kfree(frag6);
	frag_kfree(frag4);
	return success;
}

static noinline bool test_icmp(void)
{
	struct fragment *frag6, *frag4;
	struct sk_buff *skb6, *skb4;
	struct tuple tuple6, tuple4;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	bool success = true;

	/* Prepare the IPv6 packet. */
	if (is_error(init_pair6(&pair6, "1::2", 1212, "3::4", 1212)))
		return false;
	if (is_error(init_ipv6_tuple_from_pair(&tuple6, &pair6, L4PROTO_ICMP)))
		return false;
	if (is_error(create_skb_ipv6_icmp_info(&pair6, &skb6, 16)))
		return false;
	if (is_error(frag_create_from_skb(skb6, &frag6)))
		return false;

	/* Prepare the IPv4 packet. */
	if (is_error(init_pair4(&pair4, "0.0.0.4", 1024, "192.168.2.1", 1024)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple4, &pair4, L4PROTO_ICMP)))
		return false;
	if (is_error(create_skb_ipv4_icmp_info(&pair4, &skb4, 16)))
		return false;
	if (is_error(frag_create_from_skb(skb4, &frag4)))
		return false;

	/* A IPv4 packet attempts to be translated without state */
	success &= assert_equals_int(VER_DROP, ipv4_icmp4(frag4, &tuple4), "result");
	success &= assert_bib_count(0, L4PROTO_ICMP);
	success &= assert_session_count(0, L4PROTO_ICMP);

	/* IPv6 packet and gets translated correctly. */
	success &= assert_equals_int(VER_CONTINUE, ipv6_icmp6(frag6, &tuple6), "result");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.168.2.1", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	/* Now that there's state, the IPv4 packet manages to traverse. */
	success &= assert_equals_int(VER_CONTINUE, ipv4_icmp4(frag4, &tuple4), "result");
	success &= assert_bib_count(1, L4PROTO_ICMP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_ICMP, 1);
	success &= assert_session_count(1, L4PROTO_ICMP);
	success &= assert_session_exists("1::2", 1212, "3::4", 1212,
			"192.168.2.1", 1024, "0.0.0.4", 1024,
			L4PROTO_ICMP, 0);

	/* Quit */
	frag_kfree(frag6);
	frag_kfree(frag4);
	return success;
}

static noinline bool create_tcp_packet(struct fragment **frag, l3_protocol l3_proto,
		bool syn, bool rst, bool fin)
{
	struct sk_buff *skb;
	struct tcphdr *hdr_tcp;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	int error;

	switch (l3_proto) {
	case L3PROTO_IPV4:
		error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
		if (error)
			return false;
		error = create_skb_ipv4_tcp(&pair4, &skb, 100);
		if (error)
			return false;
		error = frag_create_from_skb(skb, frag);
		if (error)
			return false;
		break;
	case L3PROTO_IPV6:
		error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
		if (error)
			return false;
		error = create_skb_ipv6_tcp(&pair6, &skb, 100);
		if (error)
			return false;
		error = frag_create_from_skb(skb, frag);
		if (error)
			return false;
		break;
	}

	hdr_tcp = frag_get_tcp_hdr(*frag);
	hdr_tcp->syn = syn;
	hdr_tcp->rst = rst;
	hdr_tcp->fin = fin;

	return true;
}

static noinline bool init_tcp_session(
		unsigned char *remote6_addr, u16 remote6_id,
		unsigned char *local6_addr, u16 local6_id,
		unsigned char *local4_addr, u16 local4_id,
		unsigned char *remote4_addr, u16 remote4_id,
		enum tcp_states state,
		struct session_entry *session)
{
	if (!str_to_addr6_verbose(remote6_addr, &session->ipv6.remote.address))
		return false;
	session->ipv6.remote.l4_id = remote6_id;
	if (!str_to_addr6_verbose(local6_addr, &session->ipv6.local.address))
		return false;
	session->ipv6.local.l4_id = local6_id;

	if (!str_to_addr4_verbose(local4_addr, &session->ipv4.local.address))
		return false;
	session->ipv4.local.l4_id = local4_id;
	if (!str_to_addr4_verbose(remote4_addr, &session->ipv4.remote.address))
		return false;
	session->ipv4.remote.l4_id = remote4_id;

	session->dying_time = jiffies - msecs_to_jiffies(100);
	session->bib = NULL;
	INIT_LIST_HEAD(&session->bib_list_hook);
	INIT_LIST_HEAD(&session->expire_list_hook);
	session->l4_proto = L4PROTO_TCP;
	session->state = state;

	return true;
}

/*
#define IPV6_INIT_SESSION_ENTRY_SRC_ADDR "2001:db8:c0ca:1::1"
#define IPV6_INIT_SESSION_ENTRY_SRC_PORT 1080
#define IPV6_INIT_SESSION_ENTRY_DST_ADDR "64:ff9b::192.168.2.44"
#define IPV6_INIT_SESSION_ENTRY_DST_PORT 1080
#define IPV4_INIT_SESSION_ENTRY_SRC_ADDR "192.168.2.1"
#define IPV4_INIT_SESSION_ENTRY_SRC_PORT 1082
#define IPV4_INIT_SESSION_ENTRY_DST_ADDR "192.168.2.44"
#define IPV4_INIT_SESSION_ENTRY_DST_PORT 1082
static noinline bool init_session_entry(l4_protocol l4_proto, struct session_entry *se)
{
	struct in_addr src4;
	struct in_addr dst4;
	struct in6_addr src6;
	struct in6_addr dst6;

	if (!str_to_addr6_verbose(IPV6_INIT_SESSION_ENTRY_SRC_ADDR, &src6))
		return false;
	if (!str_to_addr6_verbose(IPV6_INIT_SESSION_ENTRY_DST_ADDR, &dst6))
		return false;
	if (!str_to_addr4_verbose(IPV4_INIT_SESSION_ENTRY_SRC_ADDR, &src4))
		return false;
	if (!str_to_addr4_verbose(IPV4_INIT_SESSION_ENTRY_DST_ADDR, &dst4))
		return false;

	se->ipv6.remote.address = src6; // X'
	se->ipv6.remote.l4_id = IPV6_INIT_SESSION_ENTRY_SRC_PORT; // x
	se->ipv6.local.address = dst6; // Y'
	se->ipv6.local.l4_id = IPV6_INIT_SESSION_ENTRY_DST_PORT; // y
	se->ipv4.local.address = src4; // (T, t)
	se->ipv4.local.l4_id = IPV4_INIT_SESSION_ENTRY_SRC_PORT; // (T, t)
	se->ipv4.remote.address = dst4; // (Z, z) or (Z(Y’),y)
	se->ipv4.remote.l4_id = IPV4_INIT_SESSION_ENTRY_DST_PORT; // (Z, z) or (Z(Y’),y)

	se->dying_time = 0;
	se->bib = NULL;
	INIT_LIST_HEAD(&se->entries_from_bib);
	INIT_LIST_HEAD(&se->expiration_node);
	se->l4_proto = l4_proto;
	se->state = CLOSED;

	return true;
}
*/

/**
 * BTW: This test doesn't assert the packet is actually sent.
 */
/*
static noinline bool test_send_probe_packet(void)
{
	struct session_entry se;
	bool success = true;

	if (!init_session_entry(L4PROTO_TCP, &se))
		return false;

	log_debug("Sending a packet, catch it!");
	success &= assert_true(send_probe_packet(&se), "Test if we can send a probe packet.");

	return success;
}
*/

static noinline bool test_tcp_closed_state_handle_6(void)
{
	struct session_entry *session;
	struct tuple tuple;
	struct fragment *frag;
	struct ipv6_pair pair6;
	bool success = true;

	/* Prepare */
	if (is_error(init_pair6(&pair6, "1::2", 1212, "3::4", 3434)))
		return false;
	if (is_error(init_ipv6_tuple_from_pair(&tuple, &pair6, L4PROTO_TCP)))
		return false;
	if (!create_tcp_packet(&frag, L3PROTO_IPV6, true, false, false))
		return false;

	/* Evaluate */
	success &= assert_true(tcp_closed_state_handle(frag, &tuple), "V6 syn-result");

	/* Validate */
	session = session_get(&tuple);
	success &= assert_not_null(session, "V6 syn-session.");
	if (session)
		success &= assert_equals_u8(V6_INIT, session->state, "V6 syn-state");

	frag_kfree(frag);
	return success;
}

/*
 * A V6 SYN packet arrives.
 */
static noinline bool test_tcp_v4_init_state_handle_v6syn(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	if (!init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765, V4_INIT,
			&session))
		return false;
	if (!create_tcp_packet(&frag, L3PROTO_IPV6, true, false, false))
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_init_state_handle(frag, &session), "V6 syn-result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "V6 syn-state");
	success &= assert_true(session.dying_time > jiffies, "V6 syn-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v4_init_state_handle_else(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_INIT, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, true, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_init_state_handle(frag, &session), "else-result");
	success &= assert_equals_u8(V4_INIT, session.state, "else-state");
	success &= assert_true(session.dying_time < jiffies, "else-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V4 SYN packet arrives.
 */
static noinline bool test_tcp_v6_init_state_handle_v4syn(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, true, false, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_init_state_handle(frag, &session),
			"V4 syn-result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "V4 syn-state");
	success &= assert_true(session.dying_time > jiffies, "V4 syn-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V6 SYN packet arrives.
 */
static noinline bool test_tcp_v6_init_state_handle_v6syn(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, true, false, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_init_state_handle(frag, &session),
			"V6 syn-result");
	success &= assert_equals_u8(V6_INIT, session.state, "V6 syn-state");
	success &= assert_true(session.dying_time > jiffies, "V6 syn-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v6_init_state_handle_else(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_INIT, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, true, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_init_state_handle(frag, &session), "else-result");
	success &= assert_equals_u8(V6_INIT, session.state, "else-state");
	success &= assert_true(session.dying_time < jiffies, "else-lifetime");

	frag_kfree(frag);
	return success;
}
/*
 * A V4 FIN packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v4fin(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, false, false, true);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle(frag, &session), "result");
	success &= assert_equals_u8(V4_FIN_RCV, session.state, "V4 fin-state");
	success &= assert_true(session.dying_time < jiffies, "V4 fin-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V6 FIN packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v6fin(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, false, true);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle(frag, &session), "result");
	success &= assert_equals_u8(V6_FIN_RCV, session.state, "V6 fin-state");
	success &= assert_true(session.dying_time < jiffies, "V6 fin-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V4 RST packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v4rst(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
				ESTABLISHED, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, true, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle(frag, &session), "result");
	success &= assert_equals_u8(TRANS, session.state, "V4 rst-state");
	success &= assert_true(session.dying_time > jiffies, "V4 rst-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V6 RST packet arrives.
 */
static noinline bool test_tcp_established_state_handle_v6rst(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, true, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle(frag, &session), "result");
	success &= assert_equals_u8(TRANS, session.state, "V6 rst-state");
	success &= assert_true(session.dying_time > jiffies, "V6 rst-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_established_state_handle_else(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			ESTABLISHED, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, true, false, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_established_state_handle(frag, &session), "result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V6 FIN packet arrives.
 */
static noinline bool test_tcp_v4_fin_rcv_state_handle_v6fin(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_FIN_RCV, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, false, true);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_fin_rcv_state_handle(frag, &session), "V6 fin-result");
	success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session.state, "V6 fin-state");
	success &= assert_true(session.dying_time > jiffies, "V6 fin-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v4_fin_rcv_state_handle_else(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V4_FIN_RCV, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, true, false, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v4_fin_rcv_state_handle(frag, &session), "else-result");
	success &= assert_equals_u8(V4_FIN_RCV, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V4 FIN packet arrives.
 */
static noinline bool test_tcp_v6_fin_rcv_state_handle_v4fin(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_FIN_RCV, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, false, false, true);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_fin_rcv_state_handle(frag, &session), "V4 fin-result");
	success &= assert_equals_u8(V4_FIN_V6_FIN_RCV, session.state, "V4 fin-state");
	success &= assert_true(session.dying_time > jiffies, "V4 fin-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_v6_fin_rcv_state_handle_else(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			V6_FIN_RCV, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, true, false, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_v6_fin_rcv_state_handle(frag, &session), "else-result");
	success &= assert_equals_u8(V6_FIN_RCV, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * A V4 RST packet arrives.
 */
static noinline bool test_tcp_trans_state_handle_v4rst(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, false, true, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_trans_state_handle(frag, &session), "V4 rst-result");
	success &= assert_equals_u8(TRANS, session.state, "V4 rst-state");
	success &= assert_true(session.dying_time < jiffies, "V4 rst-lifetime");

	frag_kfree(frag);
	return success;
}

/*
* A V6 RST packet arrives.
*/
static noinline bool test_tcp_trans_state_handle_v6rst(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, true, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_trans_state_handle(frag, &session), "V6 rst-result");
	success &= assert_equals_u8(TRANS, session.state, "V6 rst-state");
	success &= assert_true(session.dying_time < jiffies, "V6 rst-lifetime");

	frag_kfree(frag);
	return success;
}

/*
 * Something else arrives.
 */
static noinline bool test_tcp_trans_state_handle_else(void)
{
	struct session_entry session;
	struct fragment *frag;
	bool success = true;

	/* Prepare */
	success &= init_tcp_session("1::2", 1212, "3::4", 3434, "5.6.7.8", 5678, "8.7.6.5", 8765,
			TRANS, &session);
	success &= create_tcp_packet(&frag, L3PROTO_IPV4, true, false, false);
	if (!success)
		return false;

	/* Evaluate */
	success &= assert_true(tcp_trans_state_handle(frag, &session), "else-result");
	success &= assert_equals_u8(ESTABLISHED, session.state, "else-state");
	success &= assert_true(session.dying_time > jiffies, "else-lifetime");

	frag_kfree(frag);
	return success;
}

/**
 * We'll just chain a handful of packets, since testing every combination would take forever and
 * the inner functions were tested above anyway.
 * The chain is V6 SYN --> V4 SYN --> V6 RST --> V6 SYN.
 */
static noinline bool test_tcp(void)
{
	bool success = true;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple6;
	struct tuple tuple4;
	struct fragment *frag;

	if (is_error(init_pair6(&pair6, "1::2", 1212, "3::4", 3434)))
		return false;
	if (is_error(init_ipv6_tuple_from_pair(&tuple6, &pair6, L4PROTO_TCP)))
		return false;

	if (is_error(init_pair4(&pair4, "0.0.0.4", 3434, "192.168.2.1", 1024)))
		return false;
	if (is_error(init_ipv4_tuple_from_pair(&tuple4, &pair4, L4PROTO_TCP)))
		return false;

	/* V6 SYN */
	if (!create_tcp_packet(&frag, L3PROTO_IPV6, true, false, false))
		return false;

	success &= assert_equals_int(VER_CONTINUE, tcp(frag, &tuple6), "Closed-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.168.2.1", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, V6_INIT);

	frag_kfree(frag);

	/* V4 SYN */
	if (!create_tcp_packet(&frag, L3PROTO_IPV4, true, false, false))
		return false;

	success &= assert_equals_int(VER_CONTINUE, tcp(frag, &tuple4), "V6 init-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.168.2.1", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, ESTABLISHED);

	frag_kfree(frag);

	/* V6 RST */
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, false, true, false);

	success &= assert_equals_int(VER_CONTINUE, tcp(frag, &tuple6), "Established-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.168.2.1", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, TRANS);

	frag_kfree(frag);

	/* V6 SYN */
	success &= create_tcp_packet(&frag, L3PROTO_IPV6, true, false, false);

	success &= assert_equals_int(VER_CONTINUE, tcp(frag, &tuple6), "Trans-result");
	success &= assert_bib_count(1, L4PROTO_TCP);
	success &= assert_bib_exists("1::2", 1212, "192.168.2.1", 1024, L4PROTO_TCP, 1);
	success &= assert_session_count(1, L4PROTO_TCP);
	success &= assert_session_exists("1::2", 1212, "3::4", 3434,
			"192.168.2.1", 1024, "0.0.0.4", 3434,
			L4PROTO_TCP, ESTABLISHED);

	frag_kfree(frag);

	return success;
}

static noinline bool init_full(void)
{
	int error;

	error = pktmod_init();
	if (error)
		goto fail;
	error = pool6_init(NULL, 0);
	if (error)
		goto fail;
	error = pool4_init(NULL, 0);
	if (error)
		goto fail;
	error = bib_init();
	if (error)
		goto fail;
	error = session_init();
	if (error)
		goto fail;
	error = filtering_init();
	if (error)
		goto fail;

	return true;

fail:
	return false;
}

static noinline bool init_filtering_only(void)
{
	if (is_error(pktmod_init()))
		return false;
	if (is_error(filtering_init()))
		return false;

	return true;
}

static void end_full(void)
{
	filtering_destroy();
	session_destroy();
	bib_destroy();
	pool4_destroy();
	pool6_destroy();
	pktmod_destroy();
}

static void end_filtering_only(void)
{
	filtering_destroy();
	pktmod_destroy();
}

#define TEST_FILTERING_ONLY(fn, name) \
		INIT_CALL_END(init_filtering_only(), fn, end_filtering_only(), name)
static int __init filtering_test_init(void)
{
	START_TESTS("Filtering and Updating");

	/* General */
	CALL_TEST(test_extract_ipv4_from_ipv6(), "test_extract_ipv4_from_ipv6");
	CALL_TEST(test_embed_ipv4_in_ipv6(), "test_embed_ipv4_in_ipv6");
	INIT_CALL_END(init_full(), test_allocate_ipv4_transport_address(), end_full(), "allocate addr");
	INIT_CALL_END(init_full(), test_allocate_ipv4_transport_address_digger(), end_full(), "digger");
	INIT_CALL_END(init_full(), test_filtering_and_updating(), end_full(), "core function");

	/* UDP */
	INIT_CALL_END(init_full(), test_udp(), end_full(), "UDP");

	/* ICMP */
	INIT_CALL_END(init_full(), test_icmp(), end_full(), "ICMP");

	/* TCP */
	/* CALL_TEST(test_send_probe_packet(), "test_send_probe_packet"); */
	INIT_CALL_END(init_full(), test_tcp_closed_state_handle_6(), end_full(), "TCP-CLOSED-6");
	/* Not implemented yet! */
	/* INIT_CALL_END(init_full(), test_tcp_closed_state_handle_4(), end_full(), "TCP-CLOSED-4"); */
	TEST_FILTERING_ONLY(test_tcp_v4_init_state_handle_v6syn(), "TCP-V4 INIT-V6 syn");
	TEST_FILTERING_ONLY(test_tcp_v4_init_state_handle_else(), "TCP-V4 INIT-else");
	TEST_FILTERING_ONLY(test_tcp_v6_init_state_handle_v6syn(), "TCP-V6 INIT-V6 SYN");
	TEST_FILTERING_ONLY(test_tcp_v6_init_state_handle_v4syn(), "TCP-V6 INIT-V4 SYN");
	TEST_FILTERING_ONLY(test_tcp_v6_init_state_handle_else(), "TCP-V6 INIT-else");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v4fin(), "TCP-established-V4 fin");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v6fin(), "TCP-established-V6 fin");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v4rst(), "TCP-established-V4 rst");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_v6rst(), "TCP-established-V6 rst");
	TEST_FILTERING_ONLY(test_tcp_established_state_handle_else(), "TCP-established-else");
	TEST_FILTERING_ONLY(test_tcp_v4_fin_rcv_state_handle_v6fin(), "TCP-V4 FIN RCV-V6 fin");
	TEST_FILTERING_ONLY(test_tcp_v4_fin_rcv_state_handle_else(), "TCP-V4 FIN RCV-else");
	TEST_FILTERING_ONLY(test_tcp_v6_fin_rcv_state_handle_v4fin(), "TCP-V6 FIN RCV-v4fin");
	TEST_FILTERING_ONLY(test_tcp_v6_fin_rcv_state_handle_else(), "TCP-V6 FIN RCV-else");
	TEST_FILTERING_ONLY(test_tcp_trans_state_handle_v6rst(), "TCP-TRANS-V6 rst");
	TEST_FILTERING_ONLY(test_tcp_trans_state_handle_v4rst(), "TCP-TRANS-V4 rst");
	TEST_FILTERING_ONLY(test_tcp_trans_state_handle_else(), "TCP-TRANS-else");
	INIT_CALL_END(init_full(), test_tcp(), end_full(), "test_tcp");

	END_TESTS;
}

static void __exit filtering_test_exit(void)
{
	/* No code. */
}

module_init(filtering_test_init);
module_exit(filtering_test_exit);
