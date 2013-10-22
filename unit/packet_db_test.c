#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/validator.h"
#include "nat64/unit/types.h"
#include "nat64/comm/str_utils.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

#define GENERATE_FOR_EACH true
#include "packet_db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Packet database test");


static int pktdb_counter(struct packet *pkt, void *arg)
{
	unsigned int *int_arg = arg;
	(*int_arg)++;
	return 0;
}

static int pkt_fragment_count(struct packet *pkt)
{
	struct fragment *frag;
	int i = 0;

	list_for_each_entry(frag, &pkt->fragments, next) {
		i++;
	}

	return i;
}

static bool validate_packet_ipv6(struct packet *pkt, int fragment_count, u16 total_bytes)
{
	unsigned int expected_dying_time;
	bool success = true;

	success &= validate_fragment_count(pkt, fragment_count);
	success &= assert_equals_u16(total_bytes, pkt->total_bytes, "Total bytes");
	success &= assert_equals_u16(pkt->total_bytes, pkt->current_bytes, "Current bytes");

	if ( pkt_fragment_count(pkt) == 1 &&  pkt->total_bytes == pkt->current_bytes )
		success &= assert_equals_u32( 0, pkt->fragment_id, "Fragment identification (non fragment)");
	else
		success &= assert_equals_u32(1234, pkt->fragment_id, "Fragment identification");
	expected_dying_time = jiffies_to_msecs(jiffies) + FRAGMENT_MIN;
	success &= assert_true(expected_dying_time - 100 < pkt->dying_time
			&& pkt->dying_time < expected_dying_time + 100,
			"Dying time");

	/*
	success &= assert_equals_int(L4PROTO_UDP, pkt->proto, "L4 protocol");
	success &= assert_equals_ipv6_str("1::2", &pkt->addr.ipv6.src, "Source address");
	success &= assert_equals_ipv6_str("3::4", &pkt->addr.ipv6.dst, "Destination address");
	TODO: Validate ports also.
	 */

	success &= assert_true(list_empty(&pkt->pkt_list_node), "Not linked");

	return success;
}

static bool validate_packet_ipv4(struct packet *pkt, int fragment_count, u16 total_bytes)
{
	unsigned int expected_dying_time;
	bool success = true;

	success &= validate_fragment_count(pkt, fragment_count);
	success &= assert_equals_u16(total_bytes, pkt->total_bytes, "Total bytes");
	success &= assert_equals_u16(pkt->total_bytes, pkt->current_bytes, "Current bytes");
	success &= assert_equals_u32(1234, pkt->fragment_id, "Fragment identification");
	expected_dying_time = jiffies_to_msecs(jiffies) + FRAGMENT_MIN;
	success &= assert_true(expected_dying_time - 100 < pkt->dying_time
			&& pkt->dying_time < expected_dying_time + 100,
			"Dying time");

//	success &= assert_equals_int(L4PROTO_UDP, pkt->proto, "L4 protocol");
//	success &= assert_equals_ipv4_str("8.7.6.5", &pkt->addr.ipv4.src, "Source address");
//	success &= assert_equals_ipv4_str("5.6.7.8", &pkt->addr.ipv4.dst, "Destination address");

	success &= assert_true(list_empty(&pkt->pkt_list_node), "Not linked");

	return success;
}

static bool validate_fragment(struct fragment *frag, struct sk_buff *skb, bool has_l4_hdr)
{
	bool success = true;

	success &= assert_equals_ptr(skb, frag->skb, "SKB");

	if ( frag->l3_hdr.proto == L3PROTO_IPV4 ) {
		success &= assert_equals_int(htons(ETH_P_IP), skb->protocol, "Frag-L3 protocol");
		success &= assert_equals_int(sizeof(struct iphdr), frag->l3_hdr.len, "Frag-L3 header length");
	} else if ( frag->l3_hdr.proto == L3PROTO_IPV6 ) {
		u32 l3_hdr_len = sizeof(struct ipv6hdr);
		l3_hdr_len += (frag_get_fragment_hdr(frag)) ? sizeof(struct frag_hdr): 0;

		success &= assert_equals_int(htons(ETH_P_IPV6), skb->protocol, "Frag-L3 protocol");
		success &= assert_equals_int(l3_hdr_len, frag->l3_hdr.len, "Frag-L3 header length");
	} else {
		success &= assert_true(false, "Frag-L3 Invalid protocol");
	}
	success &= assert_equals_ptr(skb_network_header(skb), frag->l3_hdr.ptr, "Frag-L3 header");
	success &= assert_false(frag->l3_hdr.ptr_needs_kfree, "Frag-L3 header needs to be freed");

	if (has_l4_hdr) {
		success &= assert_equals_int(L4PROTO_UDP, frag->l4_hdr.proto, "Frag-L4 protocol");
		success &= assert_equals_int(sizeof(struct udphdr), frag->l4_hdr.len, "Frag-L4 header length");
		success &= assert_equals_ptr(skb_transport_header(skb), frag->l4_hdr.ptr, "Frag-L4 header");
		success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "Frag-L4 header needs to be freed");
	} else {
		success &= assert_equals_int(L4PROTO_NONE, frag->l4_hdr.proto, "Frag-L4 protocol");
		success &= assert_equals_int(0, frag->l4_hdr.len, "Frag-L4 header length");
		success &= assert_null(frag->l4_hdr.ptr, "Frag-L4 header");
//		success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "Frag-L4 header needs to be freed");
	}

	success &= assert_equals_int(100, frag->payload.len, "Frag-Payload lenght");
	if (has_l4_hdr) {
		void *expected_payload = skb_transport_header(skb) + sizeof(struct udphdr);
		success &= assert_equals_ptr(expected_payload, frag->payload.ptr, "Frag-Payload with l4_hdr");
	} else {
		success &= assert_equals_ptr(skb_transport_header(skb), frag->payload.ptr, "Frag-Payload");
	}
	success &= assert_false(frag->payload.ptr_needs_kfree, "Frag-Payloads needs to be freed");

	return success;
}

static bool validate_database(int expected_count)
{
	struct list_head *node;
	int p = 0;
	bool success = true;

	/* list */
	list_for_each(node, &list) {
		p++;
	}
	success &= assert_equals_int(expected_count, p, "Packets in the list");

	/* table */
	p = 0;
	pktdb_table_for_each(&table, pktdb_counter, &p);
	success &= assert_equals_int(expected_count, p, "Packets in the hash table");

	return success;
}

static bool validate_list(struct pktdb_key *expected, int expected_count)
{
	struct packet *current_pkt;
	bool success = true;
	int c = 0;

	list_for_each_entry(current_pkt, &list, pkt_list_node) {
		if (!assert_true(c < expected_count, "List count"))
			return false;

//		if (expected[c].is_ipv6) {
//			success &= assert_equals_ipv6(&expected[c].ipv6.src, &current_pkt->addr.ipv6.src, "IPv6 Src addr");
//			success &= assert_equals_ipv6(&expected[c].ipv6.dst, &current_pkt->addr.ipv6.dst, "IPv6 Dst addr");
//		} else {
//			success &= assert_equals_ipv4(&expected[c].ipv4.src, &current_pkt->addr.ipv4.src, "IPv4 Src addr");
//			success &= assert_equals_ipv4(&expected[c].ipv4.dst, &current_pkt->addr.ipv4.dst, "IPv4 Dst addr");
//		}
		success &= assert_equals_u32(expected[c].identifier, current_pkt->fragment_id, "Fragment ID");

		c++;
	}

	return success;
}

static bool test_no_fragments_6to4(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb;
	struct ipv6_pair pair6;
	int error;
	bool success = true;

	/* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = create_skb_ipv6_udp(&pair6, &skb, 100);
	if (error)
		return false;

	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Verdict");

	/* Validate the packet. */
	success &= validate_packet_ipv6(pkt, 1, sizeof(struct udphdr) + 100);

	/* Validate the fragment. */
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb, true); /* TODO: This is intended for IPv4. */

	/* Validate the database. */
	success &= validate_database(0);

	pkt_kfree(pkt, true);
	return success;
}

static bool test_no_fragments_4to6(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb;
	struct ipv4_pair pair4;
	int error;
	bool success = true;

	/* Prepare */
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = create_skb_ipv4_udp(&pair4, &skb, 100);
	if (error)
		return false;

	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb, &pkt), "Verdict");

	/* Validate the packet. */
	success &= validate_packet_ipv4(pkt, 1, sizeof(struct udphdr) + 100);

	/* Validate the fragment. */
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb, true);

	/* Validate the database. */
	success &= validate_database(0);

	pkt_kfree(pkt, true);
	return success;
}

/**
 *
 * Three packets: 	((IPv6 + frag_hdr) + udp_hdr + payload100),
 * 					((IPv6 + frag_hdr) payload100)
 * 					((IPv6 + frag_hdr) payload100)
 */
static bool test_fragments_6to4(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv6_pair pair6;
	struct ipv6hdr *hdr6;
	struct frag_hdr *hdr_frag;
	int errorx;
	bool success = true;
	u32 id1 = 1234;

	errorx = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (errorx)
		return false;

	/* First packet arrives. */
	errorx = create_skb_ipv6_udp_fragment_1(&pair6, &skb1, 100);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb1);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* Second packet arrives. */
	errorx = create_skb_ipv6_udp_fragment_n(&pair6, &skb2, 100);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb2);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(100+sizeof(struct udphdr), true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb2, &pkt), "2nd verdict");
	success &= validate_database(1);

	/* Third and final packet arrives. */
	errorx = create_skb_ipv6_udp_fragment_n(&pair6, &skb3, 100);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb3);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(200+sizeof(struct udphdr), false);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb3, &pkt), "3rd verdict");
	success &= validate_database(0);

	/* Validate the packet. */
	success &= validate_packet_ipv6(pkt, 3, sizeof(struct udphdr) + 300);

	/* Validate the fragments. */
	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, true);

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb2, false);

	log_debug("Validating the third fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, false);

	pkt_kfree(pkt, true);
	return success;
}

static bool test_fragments_4to6(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv4_pair pair4;
	struct iphdr *hdr4;
	int error;
	bool success = true;

	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;

	/* First packet arrives. */
	error = create_skb_ipv4_udp(&pair4, &skb1, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb1);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* Second packet arrives. */
	error = create_skb_ipv4_udp_fragment(&pair4, &skb2, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb2);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, sizeof(struct udphdr) + 100);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb2, &pkt), "2nd verdict");
	success &= validate_database(1);

	/* Third and final packet arrives. */
	error = create_skb_ipv4_udp_fragment(&pair4, &skb3, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb3);
	hdr4->frag_off = build_ipv4_frag_off_field(false, false, sizeof(struct udphdr) + 200);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb3, &pkt), "3rd verdict");
	success &= validate_database(0);

	/* Validate the packet. */
	success &= validate_packet_ipv4(pkt, 3, sizeof(struct udphdr) + 300);

	/* Validate the fragments. */
	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, true);

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb2, false);

	log_debug("Validating the third fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, false);

	pkt_kfree(pkt, true);
	return success;
}

/* TODO jiffies NO ES ATÓMICA. */

/**
 * Two things are being validated here:
 * - The timer deletes the correct stuff whenever it has to.
 * - multiple packets in the DB at once.
 */
static bool test_timer(void)
{
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv4_pair pair13, pair2; /* skbs 1 and 3 use pair 13. skb2 uses pair2. */
	struct sk_buff *skb4, *skb5, *skb6;
	struct ipv6_pair pair46, pair5; /* skbs 4 and 6 use pair 46. skb5 uses pair5. */
	struct pktdb_key expected_keys[6];
	struct packet *pkt, *pkt6;
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct frag_hdr *hdr_frag;
	u32 id1 = 1234;
	bool success = true;
	int errorx;
	int count = 0;

	errorx = init_pair4(&pair13, "8.7.6.5", 8765, "5.6.7.8", 5678);	/* Pkt_DB(0) */
	if (errorx)
		return false;
	errorx = init_pair4(&pair2, "11.12.13.14", 1112, "14.13.12.11", 1413); /* Pkt_DB(1) */
	if (errorx)
		return false;
	errorx = init_pair6(&pair46, "1::2", 1212, "3::4", 3434);		/* Pkt_DB(2) */
	if (errorx)
		return false;
	errorx = init_pair6(&pair5, "8::7", 8787, "6::5", 6565);		/* Pkt_DB(3) */
	if (errorx)
		return false;

	expected_keys[0].is_ipv6 = false;
	expected_keys[0].ipv4.src = pair13.remote.address;
	expected_keys[0].ipv4.dst = pair13.local.address;
	expected_keys[0].identifier = id1;

	expected_keys[1].is_ipv6 = false;
	expected_keys[1].ipv4.src = pair2.remote.address;
	expected_keys[1].ipv4.dst = pair2.local.address;
	expected_keys[1].identifier = id1;

	expected_keys[2].is_ipv6 = true;
	expected_keys[2].ipv6.src = pair46.remote.address;
	expected_keys[2].ipv6.dst = pair46.local.address;
	expected_keys[2].identifier = id1;

	expected_keys[3].is_ipv6 = true;
	expected_keys[3].ipv6.src = pair5.remote.address;
	expected_keys[3].ipv6.dst = pair5.local.address;
	expected_keys[3].identifier = id1;

	/* First packet */
	log_debug("Packet #%d", ++count);
	errorx = create_skb_ipv4_udp(&pair13, &skb1, 100);
	if (errorx)
		return false;
	hdr4 = ip_hdr(skb1);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb1, &pkt), "1st verdict");

	success &= validate_database(1);
	success &= validate_list(&expected_keys[0], 1);
	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 1");
	success &= validate_database(1);
	success &= validate_list(&expected_keys[0], 1);

	/* Second packet */
	log_debug("Packet #%d", ++count);
	errorx = create_skb_ipv4_udp_fragment(&pair2, &skb2, 100);
	if (errorx)
		return false;
	hdr4 = ip_hdr(skb2);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb2, &pkt), "2nd verdict");

	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);
	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2");
	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);

	/* Third packet */
	log_debug("Packet #%d", ++count);
	errorx = create_skb_ipv4_udp(&pair13, &skb3, 100);
	if (errorx)
		return false;
	hdr4 = ip_hdr(skb3);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, sizeof(struct udphdr) + 100);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb3, &pkt), "3rd verdict");

	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);
	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2");
	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);

	/* Fourth packet - IPv6 */
	log_debug("Packet #%d", ++count);
	errorx = create_skb_ipv6_udp_fragment_1(&pair46, &skb4, 100);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb4);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb4, &pkt6), "4th verdict");

	success &= validate_database(3);
	success &= validate_list(&expected_keys[0], 3);
	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 4");
	success &= validate_database(3);
	success &= validate_list(&expected_keys[0], 3);

	/* Fifth packet - IPv6 */
	log_debug("Packet #%d", ++count);
	errorx = create_skb_ipv6_udp_fragment_n(&pair5, &skb5, 100);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb5);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb5, &pkt6), "5th verdict");

	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);
	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 5");
	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);

	/* Sixth packet - IPv6 */
	log_debug("Packet #%d", ++count);
	errorx = create_skb_ipv6_udp_fragment_n(&pair46, &skb6, 100);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb6);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(100+sizeof(struct udphdr), true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb6, &pkt6), "6th verdict");

	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);
	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 6");
	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);

	/* After 2 seconds, the first packet should die. */
	pkt6 = container_of(list.next, struct packet, pkt_list_node);
	pkt6->dying_time = jiffies_to_msecs(jiffies) - 1;
	pkt6 = container_of(pkt6->pkt_list_node.next, struct packet, pkt_list_node);
	pkt6->dying_time = jiffies_to_msecs(jiffies) + 4000;

	success &= assert_range(3900, 4100, clean_expired_fragments(), "Timer 3");
	success &= validate_database(3);
	success &= validate_list(&expected_keys[1], 3);

	/* After a while, the second packet should die. */
	pkt6->dying_time = jiffies_to_msecs(jiffies) - 1;

	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 4");
	success &= validate_database(2);
	success &= validate_list(&expected_keys[2], 2);

	/* After 2 seconds, the third packet should die. */
	pkt6 = container_of(list.next, struct packet, pkt_list_node);
	pkt6->dying_time = jiffies_to_msecs(jiffies) - 1;
	pkt6 = container_of(pkt6->pkt_list_node.next, struct packet, pkt_list_node);
	pkt6->dying_time = jiffies_to_msecs(jiffies) + 4000;

	success &= assert_range(3900, 4100, clean_expired_fragments(), "Timer 5");
	success &= validate_database(1);
	success &= validate_list(&expected_keys[3], 1);

	/* After a while, the fourth packet should die. */
	pkt6->dying_time = jiffies_to_msecs(jiffies) - 1;

	success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 6");
	success &= validate_database(0);

	return success;
}

/**
 * Three things are being validated here:
 * - Fragments arriving in disorder.
 * - Fragments from different connections but same identifier.
 */
static bool test_conflicts(void)
{
	struct packet *pkt, *pkt6;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3;
	struct sk_buff *skb4, *skb5, *skb6;
	struct ipv4_pair pair13, pair2;
	struct ipv6_pair pair46, pair5;
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct frag_hdr *hdr_frag;
	u32 id1 = 1234;
	int error;
	bool success = true;

	error = init_pair4(&pair13, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = init_pair4(&pair2, "11.12.13.14", 1112, "14.13.12.11", 1413);
	if (error)
		return false;
	error = init_pair6(&pair46, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = init_pair6(&pair5, "8::7", 8787, "6::5", 6565);
	if (error)
		return false;

	/* First packet arrives. */
	error = create_skb_ipv4_udp_fragment(&pair13, &skb1, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb1);
	hdr4->frag_off = build_ipv4_frag_off_field(false, false, sizeof(struct udphdr) + 100);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* Second packet arrives. */
	error = create_skb_ipv4_udp_fragment(&pair2, &skb2, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb2);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb2, &pkt), "2nd verdict");
	success &= validate_database(2);

	/* Third and final packet arrives. */
	error = create_skb_ipv4_udp(&pair13, &skb3, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb3);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb3, &pkt), "3rd verdict");
	success &= validate_database(1);

	/* Validate the packet. */
	success &= validate_packet_ipv4(pkt, 2, sizeof(struct udphdr) + 200);

	/* Validate the fragments. */
	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, false);

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, true);

	/* Fourth packet arrives - IPv6. */
	log_debug("Start with IPv6");
	error = create_skb_ipv6_udp_fragment_n(&pair46, &skb4, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb4);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(100+sizeof(struct udphdr), false);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb4, &pkt6), "4th verdict");
	success &= validate_database(2);

	/* Fifth packet arrives - IPv6. */
	error = create_skb_ipv6_udp_fragment_n(&pair5, &skb5, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb5);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(100+sizeof(struct udphdr), true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, pkt_from_skb(skb5, &pkt6), "5th verdict");
	success &= validate_database(3);

	/* Sixth and final packet arrives - IPv6. */
	error = create_skb_ipv6_udp_fragment_1(&pair46, &skb6, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb6);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_CONTINUE, pkt_from_skb(skb6, &pkt6), "6th verdict");
	success &= validate_database(2);

	/* Validate the packet - IPv6. */
	success &= validate_packet_ipv6(pkt6, 2, sizeof(struct udphdr) + 200);

	/* Validate the fragments - IPv6. */
	log_debug("Validating the third fragment...");
	frag = container_of(pkt6->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb4, false);

	log_debug("Validating the fourth fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb6, true);

	pkt_kfree(pkt, true);
	return success;
}

int init_module(void)
{
	/*
	 * Cosas que no estamos probando:
	 * - que llegue un mismo fragmento dos veces
	 * - 6 a 4.
	 */

	START_TESTS("Packet database");

	pktmod_init();
	pktdb_init();

	CALL_TEST(test_no_fragments_4to6(), "Unfragmented IPv4 packet arrives.");
	CALL_TEST(test_no_fragments_6to4(), "Unfragmented IPv6 packet arrives.");
	CALL_TEST(test_fragments_4to6(), "3 fragmented IPv4 packets arrive.");
	CALL_TEST(test_fragments_6to4(), "3 fragmented IPv6 packets arrive.");
	CALL_TEST(test_timer(), "Timer test.");
	CALL_TEST(test_conflicts(), "Conflicts test.");

	pktdb_destroy();
	pktmod_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
