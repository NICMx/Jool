/*
 * send_packet_test.c
 *
 *  Created on: Oct 14, 2014
 *      Author: dhernandez
 */

#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/printk.h> /* pr_* */
#include <linux/ipv6.h>
#include <linux/time.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dhernandez");
MODULE_DESCRIPTION("Unit tests for the send_packet_module");
MODULE_ALIAS("nat64_test_send_packet");

#include "nat64/comm/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/types.h"
#include "nat64/unit/validator.h"

#include "../mod/send_packet.c"

static bool init(void)
{
	/* No code. */
	return true;
}

static void end(void)
{
	/* No code. */
}

static bool validate_frag6(struct sk_buff *skb, bool is_first, bool is_last, u16 offset,
		u16 payload_len, u16 payload_offset, struct tuple *tuple, l4_protocol l4proto,
		u16 total_payload)
{
	size_t l4hdr_size;
	u16 l4_next_hdr;
	u16 mf = is_last ? 0 : IP6_MF;
	u16 hdr_payload_len;

	switch (l4proto) {
	case (L4PROTO_TCP):
		l4hdr_size = sizeof(struct tcphdr);
		l4_next_hdr = NEXTHDR_TCP;
		break;
	case (L4PROTO_UDP):
		l4hdr_size = sizeof(struct udphdr);
		l4_next_hdr = NEXTHDR_UDP;
		break;
	case (L4PROTO_ICMP):
		l4hdr_size = sizeof(struct icmp6hdr);
		l4_next_hdr = NEXTHDR_ICMP;
		break;
	default:
		log_debug("Invalid l4 protocol: %u", l4proto);
		return false;
	}
	hdr_payload_len = sizeof(struct frag_hdr) + (is_first ? l4hdr_size : 0)	+ payload_len;

	if (!skb) {
		log_err("The skb is NULL.");
		return false;
	}

	if (!validate_cb_l3(skb, L3PROTO_IPV6, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_cb_l4(skb, l4proto, is_first ? l4hdr_size : 0))
		return false;
	if (!validate_cb_payload(skb, payload_len))
		return false;

	if (!validate_ipv6_hdr(ipv6_hdr(skb), hdr_payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(get_extension_header(ipv6_hdr(skb), NEXTHDR_FRAGMENT), offset, mf,
			l4_next_hdr))
		return false;
	switch (l4proto) {
	case (L4PROTO_TCP):
		if (is_first && !validate_tcp_hdr(tcp_hdr(skb), tuple))
			return false;
		break;
	case (L4PROTO_UDP):
		if (is_first && !validate_udp_hdr(udp_hdr(skb), total_payload, tuple))
			return false;
		break;
	case (L4PROTO_ICMP):
		/*id field is not used in the validate_icmp6_hdr function.*/
		if (is_first && !validate_icmp6_hdr(icmp6_hdr(skb), 1234, tuple))
			return false;
		break;
	}

	if (!validate_payload(skb_payload(skb), payload_len, payload_offset))
		return false;

	return true;
}

static void print_skbs(struct sk_buff *skb) {
	while (skb) {
		skb_print(skb);
		skb = skb->next;
	}
}

static bool validate_frags6(struct sk_buff *skb, struct tuple *tuple, int total_frags,
		bool is_first[], bool is_last[], u16 frag_offset[], u16 payload_len[], u16 payload_offset[],
		u16 total_payload, l4_protocol l4proto)
{
	int i;
	if (!skb)
		return false;

	if (!validate_fragment_count(skb, total_frags))
		return false;

	for (i = 0; i < total_frags; i++) {
		log_debug("Validating fragment #%d", i);
		if (!validate_frag6(skb, is_first[i], is_last[i], frag_offset[i], payload_len[i],
				payload_offset[i], tuple, l4proto, total_payload))
			return false;
		skb = skb->next;
	}

	return true;
}

static bool divide_skb_test(l4_protocol l4_proto,
		int (*create_skb6_frag_fn)(struct tuple *, struct sk_buff **, u16, u16, bool, bool, u16, u8))
{
	struct sk_buff *skb6 = NULL;
	struct tuple tuple6;
	bool result = true;
	u16 total_payload = 3000;

	/* IPv6 Parameters. (To evaluate). */
	bool is_first[] = {true, false, false};
	bool is_last[] = {false, false, true};
	u16 frag6_offset[] = {0, 1232, 2464};
	u16 *payload6_len, *payload_offset;
	int total_frags6 = 3;

	u16 total_l4_len;
	u16 payload6_udp_icmp_len[] = {1224, 1232, 544};
	u16 payload_udp_icmp_offset[] = {0, 1224, 2456};
	u16 payload6_tcp_len[] = {1212, 1232, 556};
	u16 payload_tcp_offset[] = {0, 1212, 2444};

	if (l4_proto == L4PROTO_TCP) {
		payload6_len = payload6_tcp_len;
		payload_offset = payload_tcp_offset;
		total_l4_len = sizeof(struct tcphdr);
	} else {
		payload6_len = payload6_udp_icmp_len;
		payload_offset = payload_udp_icmp_offset;
		if (l4_proto == L4PROTO_UDP)
			total_l4_len = sizeof(struct udphdr) + total_payload;
		else
			total_l4_len = sizeof(struct icmphdr);
	}

	if (init_ipv6_tuple(&tuple6, "1::1", 6000, "64:ff9b::192.0.2.7", 4000, l4_proto) != 0)
		return false;

	if (create_skb6_frag_fn(&tuple6, &skb6, total_payload, total_l4_len ,false, false, 0, 32) != 0)
		return false;

	/* Just for precaution. */
	skb6->next = NULL;
	skb6->prev = NULL;

	if (divide(skb6, 1280) != 0) {
		kfree_skb_queued(skb6);
		return false;
	}

	result = validate_frags6(skb6, &tuple6, total_frags6, is_first, is_last, frag6_offset,
			payload6_len, payload_offset, total_payload, l4_proto);

	kfree_skb_queued(skb6);
	return result;
}

static bool divide_skb6_udp(void)
{
	return divide_skb_test(L4PROTO_UDP, create_skb6_udp_frag);
}

static bool divide_skb6_icmp(void)
{
	return divide_skb_test(L4PROTO_ICMP, create_skb6_icmp_info_frag);
}

static bool divide_skb6_tcp(void)
{
	return divide_skb_test(L4PROTO_TCP, create_skb6_tcp_frag);
}

static int send_packet_test_init(void)
{
	START_TESTS("Send Packet test");

	INIT_CALL_END(init(), divide_skb6_udp(), end(), "test_send_packet IPv6 UDP fragmentation");
	INIT_CALL_END(init(), divide_skb6_icmp(), end(), "test_send_packet IPv6 ICMP fragmentation");
	INIT_CALL_END(init(), divide_skb6_tcp(), end(), "test_send_packet IPv6 TCP fragmentation");

	END_TESTS;
}

static void send_packet_test_exit(void)
{
	/* No code. */
}

module_init(send_packet_test_init);
module_exit(send_packet_test_exit);

