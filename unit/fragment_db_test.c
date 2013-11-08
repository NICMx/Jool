#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/validator.h"
#include "nat64/unit/types.h"

#define GENERATE_FOR_EACH true
#include "fragment_db.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Fragment database test");


static int fragdb_counter(struct reassembly_buffer *buffer, void *arg)
{
	unsigned int *int_arg = arg;
	(*int_arg)++;
	return 0;
}

static bool validate_packet(struct packet *pkt, int expected_frag_count)
{
	struct fragment *frag;
	int actual_frag_count = 0;
	bool found_first = false;
	bool success = true;

	list_for_each_entry(frag, &pkt->fragments, next) {
		actual_frag_count++;
		if (frag == pkt->first_fragment) {
			if (found_first) {
				log_warning("Found the first fragment more than once in the packet.");
				success = false;
			}
			found_first = true;
		}
	}

	success &= assert_equals_int(expected_frag_count, actual_frag_count, "Fragment count");
	success &= assert_true(found_first, "First fragment's presence in pkt's list");

	return success;
}

static bool validate_fragment(struct fragment *frag, struct sk_buff *skb, bool has_l4_hdr,
		bool has_frag_hdr, int payload_len)
{
	bool success = true;
	u32 l3_hdr_len;

	success &= assert_equals_ptr(skb, frag->skb, "SKB");

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		success &= assert_equals_int(L3PROTO_IPV4, frag->l3_hdr.proto, "Frag-L3 protocol");
		success &= assert_equals_int(sizeof(struct iphdr), frag->l3_hdr.len, "Frag-L3 hdr length");
		break;
	case ETH_P_IPV6:
		l3_hdr_len = sizeof(struct ipv6hdr) + (has_frag_hdr ? sizeof(struct frag_hdr) : 0);
		success &= assert_equals_int(L3PROTO_IPV6, frag->l3_hdr.proto, "Frag-L3 protocol");
		success &= assert_equals_int(l3_hdr_len, frag->l3_hdr.len, "Frag-L3 hdr length");
		break;
	default:
		success &= assert_true(false, "Frag-L3 Invalid protocol");
		break;
	}
	success &= assert_equals_ptr(skb_network_header(skb), frag->l3_hdr.ptr, "Frag-L3 hdr");
	success &= assert_false(frag->l3_hdr.ptr_needs_kfree, "Frag-L3 hdr needs to be freed");

	if (has_l4_hdr) {
		success &= assert_equals_int(L4PROTO_UDP, frag->l4_hdr.proto, "Frag-L4 protocol");
		success &= assert_equals_int(sizeof(struct udphdr), frag->l4_hdr.len, "Frag-L4 hdr length");
		success &= assert_equals_ptr(skb_transport_header(skb), frag->l4_hdr.ptr, "Frag-L4 hdr");
		success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "Frag-L4 hdr needs to be freed");
	} else {
		success &= assert_equals_int(L4PROTO_NONE, frag->l4_hdr.proto, "Frag-L4 protocol");
		success &= assert_equals_int(0, frag->l4_hdr.len, "Frag-L4 hdr length");
		success &= assert_null(frag->l4_hdr.ptr, "Frag-L4 hdr");
		success &= assert_false(frag->l4_hdr.ptr_needs_kfree, "Frag-L4 hdr needs to be freed");
	}

	success &= assert_equals_int(payload_len, frag->payload.len, "Frag-Payload length");
	if (has_l4_hdr) {
		void *expected_payload = skb_transport_header(skb) + sizeof(struct udphdr);
		success &= assert_equals_ptr(expected_payload, frag->payload.ptr, "Frag-Payload with hdr");
	} else {
		success &= assert_equals_ptr(skb_transport_header(skb), frag->payload.ptr, "Frag-Payload");
	}
	success &= assert_false(frag->payload.ptr_needs_kfree, "Frag-Payloads needs to be freed");

	return success;
}
//
static bool validate_database(int expected_count)
{
	struct list_head *node;
	int p = 0;
	bool success = true;

	/* list */
	list_for_each(node, &expire_list) {
		p++;
	}
	success &= assert_equals_int(expected_count, p, "Packets in the list");

	/* table */
	p = 0;
	fragdb_table_for_each(&table, fragdb_counter, &p);
	success &= assert_equals_int(expected_count, p, "Packets in the hash table");

	return success;
}

static bool test_no_fragments_6to4(void)
{
	struct packet *pkt;
	struct sk_buff *skb;
	struct ipv6_pair pair6;
	int error;
	bool success = true;

	/* Prepare */
	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;
	error = create_skb_ipv6_udp(&pair6, &skb, 10);
	if (error)
		return false;

	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb, &pkt), "Verdict");
	success &= validate_packet(pkt, 1);
	success &= validate_fragment(pkt->first_fragment, skb, true, false, 10);
	success &= validate_database(0);

	pkt_kfree(pkt, true);
	return success;
}

static bool test_no_fragments_4to6(void)
{
	struct packet *pkt;
	struct sk_buff *skb;
	struct ipv4_pair pair4;
	int error;
	bool success = true;

	/* Prepare */
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;
	error = create_skb_ipv4_udp(&pair4, &skb, 20);
	if (error)
		return false;

	/* Test */
	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb, &pkt), "Verdict");
	if (!success)
		return false;

	success &= validate_packet(pkt, 1);
	success &= validate_fragment(pkt->first_fragment, skb, true, false, 20);
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
	errorx = create_skb_ipv6_udp_fragment_1(&pair6, &skb1, 64 - sizeof(struct udphdr));
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb1);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* Second packet arrives. */
	errorx = create_skb_ipv6_udp_fragment_n(&pair6, &skb2, 128);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb2);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(64, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "2nd verdict");
	success &= validate_database(1);

	/* Third and final packet arrives. */
	errorx = create_skb_ipv6_udp_fragment_n(&pair6, &skb3, 192);
	if (errorx)
		return false;
	hdr6 = ipv6_hdr(skb3);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(192, false);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb3, &pkt), "3rd verdict");
	success &= validate_database(0);

	/* Validate the packet. */
	success &= validate_packet(pkt, 3);

	/* Validate the fragments. */
	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, true, true, 64 - sizeof(struct udphdr));

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb2, false, true, 128);

	log_debug("Validating the third fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, false, true, 192);

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
	error = create_skb_ipv4_udp(&pair4, &skb1, 64 - sizeof(struct udphdr));
	if (error)
		return false;
	hdr4 = ip_hdr(skb1);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* Second packet arrives. */
	error = create_skb_ipv4_udp_fragment(&pair4, &skb2, 128);
	if (error)
		return false;
	hdr4 = ip_hdr(skb2);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 64);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "2nd verdict");
	success &= validate_database(1);

	/* Third and final packet arrives. */
	error = create_skb_ipv4_udp_fragment(&pair4, &skb3, 192);
	if (error)
		return false;
	hdr4 = ip_hdr(skb3);
	hdr4->frag_off = build_ipv4_frag_off_field(false, false, 192);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb3, &pkt), "3rd verdict");
	success &= validate_database(0);

	/* Validate the packet. */
	if (pkt == NULL) {
		log_debug("Nulo");
		return false;
	}
	success &= validate_packet(pkt, 3);

	/* Validate the fragments. */
	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, true, false, 64 - sizeof(struct udphdr));

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb2, false, false, 128);

	log_debug("Validating the third fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, false, false, 192);

	pkt_kfree(pkt, true);
	return success;
}

/* TODO jiffies NO ES ATÓMICA. */

//static bool validate_list(struct reassembly_buffer_key *expected, int expected_count)
//{
//	struct reassembly_buffer *current_buffer;
//	bool success = true;
//	int c = 0;
//
////	list_for_each_entry(current_buffer, &expire_list, hook) {
//		if (!assert_true(c < expected_count, "List count"))
//			return false;
//
//		switch (expected[c].l3_proto) {
//		case L3PROTO_IPV6:
//			success &= assert_equals_ipv6(&expected[c].ipv6.src_addr, &current_buffer->addr.ipv6.src,
//					"IPv6 Src addr");
//			success &= assert_equals_ipv6(&expected[c].ipv6.dst_addr, &current_buffer->addr.ipv6.dst,
//					"IPv6 Dst addr");
//			success &= assert_equals_u32(expected[c].ipv6.identification, current_buffer->fragment_id,
//					"Fragment ID");
//			break;
//		case L3PROTO_IPV4:
//			success &= assert_equals_ipv4(&expected[c].ipv4.src_addr, &current_buffer->addr.ipv4.src,
//					"IPv4 Src addr");
//			success &= assert_equals_ipv4(&expected[c].ipv4.dst_addr, &current_buffer->addr.ipv4.dst,
//					"IPv4 Dst addr");
//			success &= assert_equals_u32(expected[c].ipv4.identification, current_buffer->fragment_id,
//					"Fragment ID");
//			break;
//		}
//
//		c++;
////	}
//
//	return success;
//}
//
///**
// * Two things are being validated here:
// * - The timer deletes the correct stuff whenever it has to.
// * - multiple packets in the DB at once.
// */
//static bool test_timer(void)
//{
//	struct sk_buff *skb1, *skb2, *skb3;
//	struct ipv4_pair pair13, pair2; /* skbs 1 and 3 use pair 13. skb2 uses pair2. */
//	struct sk_buff *skb4, *skb5, *skb6;
//	struct ipv6_pair pair46, pair5; /* skbs 4 and 6 use pair 46. skb5 uses pair5. */
//	struct reassembly_buffer_key expected_keys[6];
//	struct packet *pkt, *pkt6;
//	struct iphdr *hdr4;
//	struct ipv6hdr *hdr6;
//	struct frag_hdr *hdr_frag;
//	u16 id1 = 1234;
//	bool success = true;
//	int errorx;
//	int count = 0;
//
//	errorx = init_pair4(&pair13, "8.7.6.5", 8765, "5.6.7.8", 5678);	/* Pkt_DB(0) */
//	if (errorx)
//		return false;
//	errorx = init_pair4(&pair2, "11.12.13.14", 1112, "14.13.12.11", 1413); /* Pkt_DB(1) */
//	if (errorx)
//		return false;
//	errorx = init_pair6(&pair46, "1::2", 1212, "3::4", 3434);		/* Pkt_DB(2) */
//	if (errorx)
//		return false;
//	errorx = init_pair6(&pair5, "8::7", 8787, "6::5", 6565);		/* Pkt_DB(3) */
//	if (errorx)
//		return false;
//
//	expected_keys[0].l3_proto = L3PROTO_IPV4;
//	expected_keys[0].ipv4.src_addr = pair13.remote.address;
//	expected_keys[0].ipv4.dst_addr = pair13.local.address;
//	expected_keys[0].ipv4.identification = cpu_to_be16(id1);
//	expected_keys[0].l4_proto = NEXTHDR_UDP;
//
//	expected_keys[1].l3_proto = L3PROTO_IPV4;
//	expected_keys[1].ipv4.src_addr = pair2.remote.address;
//	expected_keys[1].ipv4.dst_addr = pair2.local.address;
//	expected_keys[1].ipv4.identification = cpu_to_be16(id1);
//	expected_keys[1].l4_proto = NEXTHDR_UDP;
//
//	expected_keys[2].l3_proto = L3PROTO_IPV6;
//	expected_keys[2].ipv6.src_addr = pair46.remote.address;
//	expected_keys[2].ipv6.dst_addr = pair46.local.address;
//	expected_keys[2].ipv6.identification = cpu_to_be32(id1);
//	expected_keys[2].l4_proto = NEXTHDR_UDP;
//
//	expected_keys[3].l3_proto = L3PROTO_IPV6;
//	expected_keys[3].ipv6.src_addr = pair5.remote.address;
//	expected_keys[3].ipv6.dst_addr = pair5.local.address;
//	expected_keys[3].ipv6.identification = cpu_to_be32(id1);
//	expected_keys[3].l4_proto = NEXTHDR_UDP;
//
//	/* First packet */
//	log_debug("Packet #%d", ++count);
//	errorx = create_skb_ipv4_udp(&pair13, &skb1, 100);
//	if (errorx)
//		return false;
//	hdr4 = ip_hdr(skb1);
//	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
//	hdr4->check = 0;
//	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);
//
//	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "1st verdict");
//
//	success &= validate_database(1);
//	success &= validate_list(&expected_keys[0], 1);
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 1"); */
//	clean_expired_buffers();
//	success &= validate_database(1);
//	success &= validate_list(&expected_keys[0], 1);
//
//	/* Second packet */
//	log_debug("Packet #%d", ++count);
//	errorx = create_skb_ipv4_udp_fragment(&pair2, &skb2, 100);
//	if (errorx)
//		return false;
//	hdr4 = ip_hdr(skb2);
//	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
//	hdr4->check = 0;
//	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);
//
//	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "2nd verdict");
//
//	success &= validate_database(2);
//	success &= validate_list(&expected_keys[0], 2);
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2"); */
//	clean_expired_buffers();
//	success &= validate_database(2);
//	success &= validate_list(&expected_keys[0], 2);
//
//	/* Third packet */
//	log_debug("Packet #%d", ++count);
//	errorx = create_skb_ipv4_udp(&pair13, &skb3, 100);
//	if (errorx)
//		return false;
//	hdr4 = ip_hdr(skb3);
//	hdr4->frag_off = build_ipv4_frag_off_field(false, true, sizeof(struct udphdr) + 100);
//	hdr4->check = 0;
//	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);
//
//	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb3, &pkt), "3rd verdict");
//
//	success &= validate_database(2);
//	success &= validate_list(&expected_keys[0], 2);
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2"); */
//	clean_expired_buffers();
//	success &= validate_database(2);
//	success &= validate_list(&expected_keys[0], 2);
//
//	/* Fourth packet - IPv6 */
//	log_debug("Packet #%d", ++count);
//	errorx = create_skb_ipv6_udp_fragment_1(&pair46, &skb4, 100);
//	if (errorx)
//		return false;
//	hdr6 = ipv6_hdr(skb4);
//	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
//	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
//	hdr_frag->identification = cpu_to_be32(id1);
//
//	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb4, &pkt6), "4th verdict");
//
//	success &= validate_database(3);
//	success &= validate_list(&expected_keys[0], 3);
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 4"); */
//	clean_expired_buffers();
//	success &= validate_database(3);
//	success &= validate_list(&expected_keys[0], 3);
//
//	/* Fifth packet - IPv6 */
//	log_debug("Packet #%d", ++count);
//	errorx = create_skb_ipv6_udp_fragment_n(&pair5, &skb5, 100);
//	if (errorx)
//		return false;
//	hdr6 = ipv6_hdr(skb5);
//	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
//	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
//	hdr_frag->identification = cpu_to_be32(id1);
//
//	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb5, &pkt6), "5th verdict");
//
//	success &= validate_database(4);
//	success &= validate_list(&expected_keys[0], 4);
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 5"); */
//	clean_expired_buffers();
//	success &= validate_database(4);
//	success &= validate_list(&expected_keys[0], 4);
//
//	/* Sixth packet - IPv6 */
//	log_debug("Packet #%d", ++count);
//	errorx = create_skb_ipv6_udp_fragment_n(&pair46, &skb6, 100);
//	if (errorx)
//		return false;
//	hdr6 = ipv6_hdr(skb6);
//	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
//	hdr_frag->frag_off = build_ipv6_frag_off_field(100+sizeof(struct udphdr), true);
//	hdr_frag->identification = cpu_to_be32(id1);
//
//	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb6, &pkt6), "6th verdict");
//
//	success &= validate_database(4);
//	success &= validate_list(&expected_keys[0], 4);
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 6"); */
//	clean_expired_buffers();
//	success &= validate_database(4);
//	success &= validate_list(&expected_keys[0], 4);
//
//	/* After 2 seconds, the first packet should die. */
//	pkt6 = container_of(list.next, struct packet, pkt_list_node);
//	pkt6->dying_time = jiffies - 1;
//	pkt6 = container_of(pkt6->pkt_list_node.next, struct packet, pkt_list_node);
//	pkt6->dying_time = jiffies + msecs_to_jiffies(4000);
//
//	/* success &= assert_range(3900, 4100, clean_expired_fragments(), "Timer 3"); */
//	clean_expired_buffers();
//	success &= validate_database(3);
//	success &= validate_list(&expected_keys[1], 3);
//
//	/* After a while, the second packet should die. */
//	pkt6->dying_time = jiffies - 1;
//
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 4"); */
//	clean_expired_buffers();
//	success &= validate_database(2);
//	success &= validate_list(&expected_keys[2], 2);
//
//	/* After 2 seconds, the third packet should die. */
//	pkt6 = container_of(list.next, struct packet, pkt_list_node);
//	pkt6->dying_time = jiffies - 1;
//	pkt6 = container_of(pkt6->pkt_list_node.next, struct packet, pkt_list_node);
//	pkt6->dying_time = jiffies + msecs_to_jiffies(4000);
//
//	/* success &= assert_range(3900, 4100, clean_expired_fragments(), "Timer 5"); */
//	clean_expired_buffers();
//	success &= validate_database(1);
//	success &= validate_list(&expected_keys[3], 1);
//
//	/* After a while, the fourth packet should die. */
//	pkt6->dying_time = jiffies - 1;
//
//	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 6"); */
//	clean_expired_buffers();
//	success &= validate_database(0);
//
//	return success;
//}

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

	/* Second and final fragment of packet 1 (IPv4) arrives. */
	error = create_skb_ipv4_udp_fragment(&pair13, &skb1, 24);
	if (error)
		return false;
	hdr4 = ip_hdr(skb1);
	hdr4->frag_off = build_ipv4_frag_off_field(false, false, 16);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* First fragment of packet 2 (IPv4) arrives. */
	error = create_skb_ipv4_udp_fragment(&pair2, &skb2, 32);
	if (error)
		return false;
	hdr4 = ip_hdr(skb2);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "2nd verdict");
	success &= validate_database(2);

	/* First fragment of packet 1 (IPv4) arrives. */
	error = create_skb_ipv4_udp(&pair13, &skb3, 16 - sizeof(struct udphdr));
	if (error)
		return false;
	hdr4 = ip_hdr(skb3);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb3, &pkt), "3rd verdict");
	success &= validate_database(1);

	/* Validate packet 1. */
	success &= validate_packet(pkt, 2);

	/* Validate packet 1's fragments. */
	log_debug("Validating fragment 1.2...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, false, false, 24);

	log_debug("Validating fragment 1.1...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, true, false, 8);

	/* Second fragment of packet 3 (IPv6) arrives. */
	error = create_skb_ipv6_udp_fragment_n(&pair46, &skb4, 40);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb4);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(56, false);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb4, &pkt6), "4th verdict");
	success &= validate_database(2);

	/* Second fragment of packet 4 (IPv6) arrives. */
	error = create_skb_ipv6_udp_fragment_n(&pair5, &skb5, 48);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb5);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(64, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb5, &pkt6), "5th verdict");
	success &= validate_database(3);

	/* First fragment of packet 3 (IPv6) arrives. */
	error = create_skb_ipv6_udp_fragment_1(&pair46, &skb6, 48);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb6);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb6, &pkt6), "6th verdict");
	success &= validate_database(2);

	/* Validate packet 3. */
	success &= validate_packet(pkt6, 2);

	/* Validate packet 3's fragments. */
	log_debug("Validating fragment 3.2...");
	frag = container_of(pkt6->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb4, false, true, 40);

	log_debug("Validating fragment 3.1...");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb6, true, true, 48);

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

	START_TESTS("Fragment database");

	fragdb_init();

	CALL_TEST(test_no_fragments_4to6(), "Unfragmented IPv4 packet arrives.");
	CALL_TEST(test_no_fragments_6to4(), "Unfragmented IPv6 packet arrives.");
	CALL_TEST(test_fragments_4to6(), "3 fragmented IPv4 packets arrive.");
	CALL_TEST(test_fragments_6to4(), "3 fragmented IPv6 packets arrive.");
//	CALL_TEST(test_timer(), "Timer test.");
	CALL_TEST(test_conflicts(), "Conflicts test."); /* BTW: This test is leaving the DB dirty. */

	fragdb_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
