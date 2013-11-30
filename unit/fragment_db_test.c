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


static bool create_skb_ipv4(struct sk_buff **skb, struct ipv4_pair *pair4,
		bool mf, __u16 fragment_offset, unsigned int payload_len)
{
	struct iphdr *hdr4;
	int error;

	error = (fragment_offset == 0)
			? create_skb_ipv4_udp(pair4, skb, payload_len)
			: create_skb_ipv4_udp_fragment(pair4, skb, payload_len);
	if (error)
		return false;

	hdr4 = ip_hdr(*skb);
	hdr4->frag_off = build_ipv4_frag_off_field(false, mf, fragment_offset);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);
	hdr4->id = cpu_to_be16(1234);

	return true;
}

static bool create_skb_ipv6(struct sk_buff **skb, struct ipv6_pair *pair6,
		bool mf, __u16 fragment_offset, unsigned int payload_len)
{
	struct ipv6hdr *hdr6;
	struct frag_hdr *hdr_frag;
	int error;

	error = (fragment_offset == 0)
			? create_skb_ipv6_udp_fragment_1(pair6, skb, payload_len)
			: create_skb_ipv6_udp_fragment_n(pair6, skb, payload_len);
	if (error)
		return false;

	hdr6 = ipv6_hdr(*skb);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(fragment_offset, mf);
	hdr_frag->identification = cpu_to_be32(1234);

	return true;
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

static int fragdb_counter(struct reassembly_buffer *buffer, void *arg)
{
	unsigned int *int_arg = arg;
	(*int_arg)++;
	return 0;
}

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

/**
 * Asserts the packet doesn't stay in the database if it is not a fragment.
 * IPv6-to-IPv4 direction.
 */
static bool test_no_fragments_6(void)
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

/**
 * Asserts the packet doesn't stay in the database if it is not a fragment.
 * IPv4-to-IPv6 direction.
 */
static bool test_no_fragments_4(void)
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
 * Asserts very simple fragmentation: Three fragments of a common packet arrive in the expected
 * order and there are no more fragments making noise in the database.
 * IPv4-to-IPv6 direction.
 */
static bool test_ordered_fragments_4(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv4_pair pair4;
	int error;
	bool success = true;

	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;

	/* First fragment arrives. */
	if (!create_skb_ipv4(&skb1, &pair4, true, 0, 64 - sizeof(struct udphdr)))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* Second fragment arrives. */
	if (!create_skb_ipv4(&skb2, &pair4, true, 64, 128))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "2nd verdict");
	success &= validate_database(1);

	/* Third and final fragment arrives. */
	if (!create_skb_ipv4(&skb3, &pair4, false, 192, 192))
		return false;
	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb3, &pkt), "3rd verdict");
	success &= validate_database(0);

	/* Validate the packet. */
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

/**
 * Asserts very simple fragmentation: Three fragments of a common packet arrive in the expected
 * order and there are no more fragments making noise in the database.
 * IPv6-to-IPv4 direction.
 */
static bool test_ordered_fragments_6(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv6_pair pair6;
	int error;
	bool success = true;

	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;

	/* First fragment arrives. */
	if (!create_skb_ipv6(&skb1, &pair6, true, 0, 64 - sizeof(struct udphdr)))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "1st verdict");
	success &= validate_database(1);

	/* Second fragment arrives. */
	if (!create_skb_ipv6(&skb2, &pair6, true, 64, 128))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "2nd verdict");
	success &= validate_database(1);

	/* Third and final fragment arrives. */
	if (!create_skb_ipv6(&skb3, &pair6, false, 192, 192))
		return false;
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

/**
 * Asserts messy fragmentation: Three fragments of a common packet arrive in some random order and
 * there are no more fragments making noise in the database.
 * IPv4-to-IPv6 direction.
 */
static bool test_disordered_fragments_4(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3, *skb4, *skb5;
	struct ipv4_pair pair4;
	struct reassembly_buffer *buffer;
	struct hole_descriptor *hole;
	int error;
	int success = true;

	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;

	/* Third fragment arrives. */
	if (!create_skb_ipv4(&skb3, &pair4, true, 24, 8))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb3, &pkt), "verdict 1");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 1");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(0, hole->first, "1.1.first");
	success &= assert_equals_u16(2, hole->last, "1.1.last");
	hole = list_entry(hole->hook.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(4, hole->first, "1.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "1.2.last");

	/* First fragment arrives. */
	if (!create_skb_ipv4(&skb1, &pair4, true, 0, 8))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "verdict 2");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 2");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(2, hole->first, "2.1.first");
	success &= assert_equals_u16(2, hole->last, "2.1.last");
	hole = list_entry(hole->hook.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(4, hole->first, "2.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "2.2.last");

	/* Fifth fragment arrives. */
	if (!create_skb_ipv4(&skb5, &pair4, false, 48, 8))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb5, &pkt), "verdict 3");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 3");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(2, hole->first, "3.1.first");
	success &= assert_equals_u16(2, hole->last, "3.1.last");
	hole = list_entry(hole->hook.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(4, hole->first, "3.2.first");
	success &= assert_equals_u16(5, hole->last, "3.2.last");

	/* Second fragment arrives. */
	if (!create_skb_ipv4(&skb2, &pair4, true, 16, 8))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "verdict 4");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(1, &buffer->holes, "Hole count 4");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(4, hole->first, "4.1.first");
	success &= assert_equals_u16(5, hole->last, "4.1.last");

	/* Fourth fragment arrives. */
	if (!create_skb_ipv4(&skb4, &pair4, true, 32, 16))
		return false;
	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb4, &pkt), "verdict 5");
	success &= validate_database(0);
	if (!success)
		return false;

	/* Validate the packet. */
	success &= validate_packet(pkt, 5);

	/* Validate the fragments. */
	log_debug("Fragment 3");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, false, false, 8);

	log_debug("Fragment 1");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, true, false, 8);

	log_debug("Fragment 5");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb5, false, false, 8);

	log_debug("Fragment 2");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb2, false, false, 8);

	log_debug("Fragment 4");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb4, false, false, 16);

	pkt_kfree(pkt, true);
	return success;
}

/**
 * Asserts messy fragmentation: Three fragments of a common packet arrive in some random order and
 * there are no more fragments making noise in the database.
 * IPv6-to-IPv4 direction.
 * <em>Also, and perhaps more importantly, asserts that the code doesn't cough over overlapping
 * fragments</em>.
 */
static bool test_disordered_fragments_6(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3, *skb4, *skb5, *skb6;
	struct ipv6_pair pair6;
	struct reassembly_buffer *buffer;
	struct hole_descriptor *hole;
	int error;
	int success = true;

	error = init_pair6(&pair6, "1::2", 1212, "3::4", 3434);
	if (error)
		return false;

	/* Bytes 24 through 48 arrive. */
	if (!create_skb_ipv6(&skb1, &pair6, true, 24, 24))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "verdict 1");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 1");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(0, hole->first, "1.1.first");
	success &= assert_equals_u16(2, hole->last, "1.1.last");
	hole = list_entry(hole->hook.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(6, hole->first, "1.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "1.2.last");

	/* Bytes 16 through 32 arrive. */
	if (!create_skb_ipv6(&skb2, &pair6, true, 16, 16))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "verdict 2");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 2");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(0, hole->first, "2.1.first");
	success &= assert_equals_u16(1, hole->last, "2.1.last");
	hole = list_entry(hole->hook.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(6, hole->first, "2.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "2.2.last");

	/* Bytes 40 through 56 arrive. */
	if (!create_skb_ipv6(&skb3, &pair6, true, 40, 16))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb3, &pkt), "verdict 3");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 3");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(0, hole->first, "3.1.first");
	success &= assert_equals_u16(1, hole->last, "3.1.last");
	hole = list_entry(hole->hook.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(7, hole->first, "3.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "3.2.last");

	/* Bytes 8 through 64 arrive. */
	if (!create_skb_ipv6(&skb4, &pair6, true, 8, 56))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb4, &pkt), "verdict 4");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 4");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(0, hole->first, "4.1.first");
	success &= assert_equals_u16(0, hole->last, "4.1.last");
	hole = list_entry(hole->hook.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(8, hole->first, "4.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "4.2.last");

	/* Bytes 64 through 72 arrive.*/
	if (!create_skb_ipv6(&skb5, &pair6, false, 64, 8))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb5, &pkt), "verdict 5");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, hook);
	success &= assert_list_count(1, &buffer->holes, "Hole count 5");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
	success &= assert_equals_u16(0, hole->first, "5.1.first");
	success &= assert_equals_u16(0, hole->last, "5.1.last");

	/* Bytes 0 through 8 arrive.*/
	if (!create_skb_ipv6(&skb6, &pair6, true, 0, 0))
		return false;
	success &= assert_equals_int(VER_CONTINUE, fragment_arrives(skb6, &pkt), "verdict 6");
	success &= validate_database(0);

	/* Validate the packet. */
	success &= validate_packet(pkt, 6);

	/* Validate the fragments. */
	log_debug("Fragment 24-48");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	success &= validate_fragment(frag, skb1, false, true, 24);

	log_debug("Fragment 16-32");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb2, false, true, 16);

	log_debug("Fragment 40-56");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb3, false, true, 16);

	log_debug("Fragment 8-64");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb4, false, true, 56);

	log_debug("Fragment 64-72");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb5, false, true, 8);

	log_debug("Fragment 0-8");
	frag = container_of(frag->next.next, struct fragment, next);
	success &= validate_fragment(frag, skb6, true, true, 0);

	pkt_kfree(pkt, true);
	return success;
}

static bool throw_three_ipv4_udp_fragments(__sum16 original_csum, __sum16 *result_csum)
{
	struct packet *pkt;
	struct sk_buff *skb;
	struct ipv4_pair pair4;
	struct udphdr *hdr_udp;
	int error;

	/* Init pair4 */
	error = init_pair4(&pair4, "8.7.6.5", 8765, "5.6.7.8", 5678);
	if (error)
		return false;

	/* Throw the first fragment to the DB */
	if (!create_skb_ipv4(&skb, &pair4, true, 0, 0))
		return false;
	hdr_udp = udp_hdr(skb);
	hdr_udp->check = original_csum;

	if (!assert_equals_int(VER_STOLEN, fragment_arrives(skb, &pkt), "verdict 1"))
		return false;

	/* Throw the second fragment to the DB */
	if (!create_skb_ipv4(&skb, &pair4, true, 8, 8))
		return false;

	if (!assert_equals_int(VER_STOLEN, fragment_arrives(skb, &pkt), "verdict 2"))
		return false;

	/* Throw the third fragment to the DB */
	if (!create_skb_ipv4(&skb, &pair4, false, 16, 8))
		return false;

	if (!assert_equals_int(VER_CONTINUE, fragment_arrives(skb, &pkt), "verdict 3"))
		return false;

	*result_csum = hdr_udp->check;
	pkt_kfree(pkt, true);
	return true;
}

/**
 * Asserts the database never leaves UDP checksums uncomputed.
 * IPv4-to-IPv6 direction.
 */
static bool test_udp_checksum_4(void)
{
	__sum16 result_csum;
	bool success = true;

	if (!throw_three_ipv4_udp_fragments(cpu_to_be16(0x1234), &result_csum))
		return false;
	/* Non-zero IPv4 checksums should not be mangled even if they're wrong. */
	success &= assert_equals_csum(cpu_to_be16(0x1234), result_csum, "Computed IPv4 csum");

	if (!throw_three_ipv4_udp_fragments(cpu_to_be16(0), &result_csum))
		return false;
	/* Zero-checksums should be computed. */
	success &= assert_equals_csum(cpu_to_be16(0x9529), result_csum, "Zero IPv4 csum");

	return success;
}

static bool throw_three_ipv6_udp_fragments(__sum16 original_csum, __sum16 *result_csum)
{
	struct packet *pkt;
	struct sk_buff *skb;
	struct ipv6_pair pair6;
	struct udphdr *hdr_udp;
	int error;

	/* Init pair4 */
	error = init_pair6(&pair6, "8::5", 8765, "5::8", 5678);
	if (error)
		return false;

	/* Throw the first fragment to the DB */
	if (!create_skb_ipv6(&skb, &pair6, true, 0, 0))
		return false;
	hdr_udp = udp_hdr(skb);
	hdr_udp->check = original_csum;

	if (!assert_equals_int(VER_STOLEN, fragment_arrives(skb, &pkt), "verdict 1"))
		return false;

	/* Throw the second fragment to the DB */
	if (!create_skb_ipv6(&skb, &pair6, true, 8, 8))
		return false;

	if (!assert_equals_int(VER_STOLEN, fragment_arrives(skb, &pkt), "verdict 2"))
		return false;

	/* Throw the third fragment to the DB */
	if (!create_skb_ipv6(&skb, &pair6, false, 16, 8))
		return false;

	if (!assert_equals_int(VER_CONTINUE, fragment_arrives(skb, &pkt), "verdict 3"))
		return false;

	*result_csum = hdr_udp->check;
	pkt_kfree(pkt, true);
	return true;
}

/**
 * Simply asserts the database doesn't mangle IPv6-UDP checksums.
 * IPv6-to-IPv4 direction.
 */
static bool test_udp_checksum_6(void)
{
	__sum16 result_csum;
	bool success = true;

	if (!throw_three_ipv6_udp_fragments(cpu_to_be16(0x1234), &result_csum))
		return false;
	/* IPv6 checksums should not be mangled even if they're wrong. */
	success &= assert_equals_csum(cpu_to_be16(0x1234), result_csum, "Computed IPv6 csum");

	if (!throw_three_ipv6_udp_fragments(cpu_to_be16(0), &result_csum))
		return false;
	/* IPv6 checksums should not be mangled even if they're wrong. */
	success &= assert_equals_csum(cpu_to_be16(0), result_csum, "Computed IPv6 csum");

	return success;
}

static bool validate_list(struct reassembly_buffer_key *expected, int expected_count)
{
	struct reassembly_buffer *current_buffer;
	struct fragment *frag;
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	bool success = true;
	int c = 0;

	list_for_each_entry(current_buffer, &expire_list, hook) {
		if (!assert_true(c < expected_count, "List count"))
			return false;

		frag = pkt_get_first_frag(current_buffer->pkt);

		success &= assert_equals_int(expected[c].l3_proto, frag->l3_hdr.proto, "l3-proto");
		success &= assert_equals_u8(L4PROTO_UDP, frag->l4_hdr.proto, "proto");

		switch (expected[c].l3_proto) {
		case L3PROTO_IPV6:
			hdr6 = frag_get_ipv6_hdr(frag);
			success &= assert_equals_ipv6(&expected[c].ipv6.src_addr, &hdr6->saddr, "src addr6");
			success &= assert_equals_ipv6(&expected[c].ipv6.dst_addr, &hdr6->daddr, "dst addr6");
			success &= assert_equals_u32(expected[c].ipv6.identification,
					frag_get_fragment_hdr(frag)->identification, "frag id 6");
			break;
		case L3PROTO_IPV4:
			hdr4 = frag_get_ipv4_hdr(frag);
			success &= assert_equals_u32(expected[c].ipv4.src_addr.s_addr, hdr4->saddr, "src addr4");
			success &= assert_equals_u32(expected[c].ipv4.dst_addr.s_addr, hdr4->daddr, "dst addr4");
			success &= assert_equals_u16(expected[c].ipv4.identification, hdr4->id, "frag id 4");
			break;
		}

		c++;
	}

	return success;
}

/**
 * Two things are being validated here:
 * - The timer deletes the correct stuff whenever it has to.
 * - multiple packets in the DB at once.
 * Both IPv4 and IPv6.
 */
static bool test_timer(void)
{
	struct sk_buff *skb1, *skb2, *skb3, *skb4, *skb5, *skb6;
	struct ipv4_pair pair13, pair2; /* skbs 1 and 3 use pair13. skb2 uses pair2. */
	struct ipv6_pair pair46, pair5; /* skbs 4 and 6 use pair46. skb5 uses pair5. */
	struct reassembly_buffer_key expected_keys[6];
	struct reassembly_buffer *dummy_buffer;
	struct packet *pkt;
	bool success = true;
	int errorx;

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

	expected_keys[0].l3_proto = L3PROTO_IPV4;
	expected_keys[0].ipv4.src_addr = pair13.remote.address;
	expected_keys[0].ipv4.dst_addr = pair13.local.address;
	expected_keys[0].ipv4.identification = cpu_to_be16(1234);
	expected_keys[0].l4_proto = IPPROTO_UDP;

	expected_keys[1].l3_proto = L3PROTO_IPV4;
	expected_keys[1].ipv4.src_addr = pair2.remote.address;
	expected_keys[1].ipv4.dst_addr = pair2.local.address;
	expected_keys[1].ipv4.identification = cpu_to_be16(1234);
	expected_keys[1].l4_proto = IPPROTO_UDP;

	expected_keys[2].l3_proto = L3PROTO_IPV6;
	expected_keys[2].ipv6.src_addr = pair46.remote.address;
	expected_keys[2].ipv6.dst_addr = pair46.local.address;
	expected_keys[2].ipv6.identification = cpu_to_be32(1234);
	expected_keys[2].l4_proto = NEXTHDR_UDP;

	expected_keys[3].l3_proto = L3PROTO_IPV6;
	expected_keys[3].ipv6.src_addr = pair5.remote.address;
	expected_keys[3].ipv6.dst_addr = pair5.local.address;
	expected_keys[3].ipv6.identification = cpu_to_be32(1234);
	expected_keys[3].l4_proto = NEXTHDR_UDP;

	/* Fragment 1.1 arrives (first fragment of packet 1) (IPv4). */
	if (!create_skb_ipv4(&skb1, &pair13, true, 0, 100))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb1, &pkt), "1st verdict");

	success &= validate_database(1);
	success &= validate_list(&expected_keys[0], 1);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 1"); */
	clean_expired_buffers();
	success &= validate_database(1);
	success &= validate_list(&expected_keys[0], 1);

	/* Fragment 2.1 arrives (first fragment of packet 2) (IPv4). */
	if (!create_skb_ipv4(&skb2, &pair2, true, 0, 100))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb2, &pkt), "2nd verdict");

	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2"); */
	clean_expired_buffers();
	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);

	/* Fragment 1.2 arrives (IPv4). */
	if (!create_skb_ipv4(&skb3, &pair13, true, 108, 100))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb3, &pkt), "3rd verdict");

	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2"); */
	clean_expired_buffers();
	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);

	/* Fragment 3.1 (IPv6) arrives. */
	if (!create_skb_ipv6(&skb4, &pair46, true, 0, 100))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb4, &pkt), "4th verdict");

	success &= validate_database(3);
	success &= validate_list(&expected_keys[0], 3);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 4"); */
	clean_expired_buffers();
	success &= validate_database(3);
	success &= validate_list(&expected_keys[0], 3);

	/* Fragment 4.1 (IPv6) arrives. */
	if (!create_skb_ipv6(&skb5, &pair5, true, 0, 100))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb5, &pkt), "5th verdict");

	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 5"); */
	clean_expired_buffers();
	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);

	/* Fragment 3.2 arrives (IPv6). */
	if (!create_skb_ipv6(&skb6, &pair46, true, 108, 100))
		return false;
	success &= assert_equals_int(VER_STOLEN, fragment_arrives(skb6, &pkt), "6th verdict");

	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 6"); */
	clean_expired_buffers();
	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);

	/* After 2 seconds, packet 1 should die. */
	dummy_buffer = container_of(expire_list.next, struct reassembly_buffer, hook);
	dummy_buffer->dying_time = jiffies - 1;
	dummy_buffer = container_of(dummy_buffer->hook.next, struct reassembly_buffer, hook);
	dummy_buffer->dying_time = jiffies + msecs_to_jiffies(4000);

	/* success &= assert_range(3900, 4100, clean_expired_fragments(), "Timer 3"); */
	clean_expired_buffers();
	success &= validate_database(3);
	success &= validate_list(&expected_keys[1], 3);

	/* After a while, the second packet should die. */
	dummy_buffer->dying_time = jiffies - 1;

	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 4"); */
	clean_expired_buffers();
	success &= validate_database(2);
	success &= validate_list(&expected_keys[2], 2);

	/* After 2 seconds, the third packet should die. */
	dummy_buffer = container_of(expire_list.next, struct reassembly_buffer, hook);
	dummy_buffer->dying_time = jiffies - 1;
	dummy_buffer = container_of(dummy_buffer->hook.next, struct reassembly_buffer, hook);
	dummy_buffer->dying_time = jiffies + msecs_to_jiffies(4000);

	/* success &= assert_range(3900, 4100, clean_expired_fragments(), "Timer 5"); */
	clean_expired_buffers();
	success &= validate_database(1);
	success &= validate_list(&expected_keys[3], 1);

	/* After a while, the fourth packet should die. */
	dummy_buffer->dying_time = jiffies - 1;

	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 6"); */
	clean_expired_buffers();
	success &= validate_database(0);

	return success;
}

int init_module(void)
{
	START_TESTS("Fragment database");

	if (is_error(pktmod_init()))
		return -EINVAL;
	if (is_error(fragdb_init())) {
		pktmod_destroy();
		return -EINVAL;
	}

	CALL_TEST(test_no_fragments_4(), "Unfragmented IPv4 packet arrives");
	CALL_TEST(test_no_fragments_6(), "Unfragmented IPv6 packet arrives");
	CALL_TEST(test_ordered_fragments_4(), "3 ordered IPv4 fragments");
	CALL_TEST(test_ordered_fragments_6(), "3 ordered IPv6 fragments");
	CALL_TEST(test_disordered_fragments_4(), "3 disordered IPv4 fragments");
	CALL_TEST(test_disordered_fragments_6(), "3 disordered IPv6 fragments");
	CALL_TEST(test_udp_checksum_4(), "UDP-checksum 4");
	CALL_TEST(test_udp_checksum_6(), "UDP-checksum 6");
	CALL_TEST(test_timer(), "Timer test.");

	fragdb_destroy();
	pktmod_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
