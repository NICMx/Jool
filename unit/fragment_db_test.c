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


static bool validate_packet(struct sk_buff *first_skb, int expected_frag_count)
{
	struct sk_buff *skb;
	int actual_frag_count = 1;
	bool success = true;

	success &= assert_null(first_skb->prev, "Fragment list is not backwards circular");
	if (!success)
		return false;

	success &= assert_true(is_first(first_skb), "1st frag in list is frag offset 0 fragment");

	skb = first_skb;
	while (skb->next) {
		skb = skb->next;
		actual_frag_count++;
		success &= assert_false(is_first(skb), "Other fragments aren't the first one");
		success &= assert_not_equals_ptr(first_skb, skb, "Fragment list is not forward circular");
		if (!success)
			return false;
	}

	success &= assert_equals_int(expected_frag_count, actual_frag_count, "Fragment count");
	return success;
}

static bool validate_fragment(struct sk_buff *skb, bool has_l4_hdr, bool has_frag_hdr,
		int payload_len)
{
	bool success = true;

	success &= assert_equals_int(has_l4_hdr, skb_has_l4_hdr(skb), "Presence of l4-header");
	success &= assert_equals_int(has_frag_hdr, skb_frag_hdr(skb) ? true : false,
			"Presence of fragment header");
	success &= assert_equals_int(payload_len, skb_payload_len(skb), "Payload length");

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
	struct sk_buff *skb, *full_skb;
	struct tuple tuple6;
	int error;
	bool success = true;

	/* Prepare */
	error = init_ipv6_tuple(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_UDP);
	if (error)
		return false;
	error = create_skb6_udp(&tuple6, &skb, 10, 32);
	if (error)
		return false;

	success &= assert_equals_int(VER_CONTINUE, fragdb_handle6(skb, &full_skb), "Verdict");
	success &= validate_packet(full_skb, 1);
	success &= validate_fragment(full_skb, true, false, 10);
	success &= validate_database(0);

	kfree_skb_queued(full_skb);
	return success;
}

/**
 * Asserts the packet doesn't stay in the database if it is not a fragment.
 * IPv4-to-IPv6 direction.
 */
static bool test_no_fragments_4(void)
{
	struct sk_buff *skb, *full_skb;
	struct tuple tuple4;
	int error;
	bool success = true;

	/* Prepare */
	error = init_ipv4_tuple(&tuple4, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_UDP);
	if (error)
		return false;
	error = create_skb4_udp(&tuple4, &skb, 20, 32);
	if (error)
		return false;

	/* Test */
	success &= assert_equals_int(VER_CONTINUE, fragdb_handle4(skb, &full_skb), "Verdict");
	if (!success)
		return false;

	success &= validate_packet(full_skb, 1);
	success &= validate_fragment(full_skb, true, false, 20);
	success &= validate_database(0);

	kfree_skb_queued(full_skb);
	return success;
}

/**
 * Asserts very simple fragmentation: Three fragments of a common packet arrive in the expected
 * order and there are no more fragments making noise in the database.
 * IPv4-to-IPv6 direction.
 */
static bool test_ordered_fragments_4(void)
{
	struct sk_buff *full_skb;
	struct sk_buff *skb1, *skb2, *skb3;
	struct tuple tuple4;
	int error;
	bool success = true;

	error = init_ipv4_tuple(&tuple4, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_UDP);
	if (error)
		return false;

	/* First fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb1, 64 - sizeof(struct udphdr), 384, false, true, 0,
			32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb1, &full_skb), "1st verdict");
	success &= validate_database(1);

	/* Second fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb2, 128, 384, false, true, 64, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb2, &full_skb), "2nd verdict");
	success &= validate_database(1);

	/* Third and final fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb3, 192, 384, false, false, 192, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, fragdb_handle4(skb3, &full_skb), "3rd verdict");
	success &= validate_database(0);

	/* Validate the packet. */
	success &= validate_packet(full_skb, 3);
	if (!success)
		return false;

	/* Validate the fragments. */
	log_debug("Validating the first fragment...");
	success &= validate_fragment(full_skb, true, false, 64 - sizeof(struct udphdr));

	log_debug("Validating the second fragment...");
	success &= validate_fragment(full_skb->next, false, false, 128);

	log_debug("Validating the third fragment...");
	success &= validate_fragment(full_skb->next->next, false, false, 192);

	kfree_skb_queued(full_skb);
	return success;
}

/**
 * Asserts very simple fragmentation: Three fragments of a common packet arrive in the expected
 * order and there are no more fragments making noise in the database.
 * IPv6-to-IPv4 direction.
 */
static bool test_ordered_fragments_6(void)
{
	struct sk_buff *full_skb;
	struct sk_buff *skb1, *skb2, *skb3;
	struct tuple tuple6;
	int error;
	bool success = true;

	error = init_ipv6_tuple(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_UDP);
	if (error)
		return false;

	/* First fragment arrives. */
	error = create_skb6_udp_frag(&tuple6, &skb1, 64 - sizeof(struct udphdr), 384, true, true, 0, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb1, &full_skb), "1st verdict");
	success &= validate_database(1);

	/* Second fragment arrives. */
	error = create_skb6_udp_frag(&tuple6, &skb2, 128, 384, true, true, 64, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb2, &full_skb), "2nd verdict");
	success &= validate_database(1);

	/* Third and final fragment arrives. */

	error = create_skb6_udp_frag(&tuple6, &skb3, 192, 384, true, false, 192, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, fragdb_handle6(skb3, &full_skb), "3rd verdict");
	success &= validate_database(0);

	/* Validate the packet. */
	success &= validate_packet(full_skb, 3);
	if (!success)
		return false;

	/* Validate the fragments. */
	log_debug("Validating the first fragment...");
	success &= validate_fragment(full_skb, true, true, 64 - sizeof(struct udphdr));

	log_debug("Validating the second fragment...");
	success &= validate_fragment(full_skb->next, false, true, 128);

	log_debug("Validating the third fragment...");
	success &= validate_fragment(full_skb->next->next, false, true, 192);

	kfree_skb_queued(full_skb);
	return success;
}

/**
 * Asserts messy fragmentation: Three fragments of a common packet arrive in some random order and
 * there are no more fragments making noise in the database.
 * IPv4-to-IPv6 direction.
 */
static bool test_disordered_fragments_4(void)
{
	struct sk_buff *full_skb;
	struct sk_buff *skb1, *skb2, *skb3, *skb4, *skb5;
	struct tuple tuple4;
	struct reassembly_buffer *buffer;
	struct hole_descriptor *hole;
	int error;
	int success = true;

	error = init_ipv4_tuple(&tuple4, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_UDP);
	if (error)
		return false;

	/* Third fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb3, 8, 56, false, true, 24, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb3, &full_skb), "verdict 1");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 1");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(0, hole->first, "1.1.first");
	success &= assert_equals_u16(2, hole->last, "1.1.last");
	hole = list_entry(hole->list_hook.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(4, hole->first, "1.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "1.2.last");

	/* First fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb1, 8, 56, false, true, 0, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb1, &full_skb), "verdict 2");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 2");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(2, hole->first, "2.1.first");
	success &= assert_equals_u16(2, hole->last, "2.1.last");
	hole = list_entry(hole->list_hook.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(4, hole->first, "2.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "2.2.last");

	/* Fifth fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb5, 8, 56, false, false, 48, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb5, &full_skb), "verdict 3");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 3");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(2, hole->first, "3.1.first");
	success &= assert_equals_u16(2, hole->last, "3.1.last");
	hole = list_entry(hole->list_hook.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(4, hole->first, "3.2.first");
	success &= assert_equals_u16(5, hole->last, "3.2.last");

	/* Second fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb2, 8, 56, false, true, 16, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb2, &full_skb), "verdict 4");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(1, &buffer->holes, "Hole count 4");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(4, hole->first, "4.1.first");
	success &= assert_equals_u16(5, hole->last, "4.1.last");

	/* Fourth fragment arrives. */
	error = create_skb4_udp_frag(&tuple4, &skb4, 16, 56, false, true, 32, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, fragdb_handle4(skb4, &full_skb), "verdict 5");
	success &= validate_database(0);
	if (!success)
		return false;

	/* Validate the packet. */
	success &= validate_packet(full_skb, 5);

	/* Validate the fragments. */
	log_debug("Fragment 3");
	success &= validate_fragment(full_skb->next, false, false, 8);

	log_debug("Fragment 1");
	success &= validate_fragment(full_skb, true, false, 8);

	log_debug("Fragment 5");
	success &= validate_fragment(full_skb->next->next, false, false, 8);

	log_debug("Fragment 2");
	success &= validate_fragment(full_skb->next->next->next, false, false, 8);

	log_debug("Fragment 4");
	success &= validate_fragment(full_skb->next->next->next->next, false, false, 16);

	kfree_skb_queued(full_skb);
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
	struct sk_buff *full_skb;
	struct sk_buff *skb1, *skb2, *skb3, *skb4, *skb5, *skb6;
	struct tuple tuple6;
	struct reassembly_buffer *buffer;
	struct hole_descriptor *hole;
	int error;
	int success = true;

	error = init_ipv6_tuple(&tuple6, "1::2", 1212, "3::4", 3434, L4PROTO_UDP);
	if (error)
		return false;

	/* Bytes 24 through 48 arrive. */
	error = create_skb6_udp_frag(&tuple6, &skb1, 24, 72, true, true, 24, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb1, &full_skb), "verdict 1");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 1");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(0, hole->first, "1.1.first");
	success &= assert_equals_u16(2, hole->last, "1.1.last");
	hole = list_entry(hole->list_hook.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(6, hole->first, "1.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "1.2.last");

	/* Bytes 16 through 32 arrive. */
	error = create_skb6_udp_frag(&tuple6, &skb2, 16, 72, true, true, 16, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb2, &full_skb), "verdict 2");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 2");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(0, hole->first, "2.1.first");
	success &= assert_equals_u16(1, hole->last, "2.1.last");
	hole = list_entry(hole->list_hook.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(6, hole->first, "2.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "2.2.last");

	/* Bytes 40 through 56 arrive. */
	error = create_skb6_udp_frag(&tuple6, &skb3, 16, 72, true, true, 40, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb3, &full_skb), "verdict 3");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 3");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(0, hole->first, "3.1.first");
	success &= assert_equals_u16(1, hole->last, "3.1.last");
	hole = list_entry(hole->list_hook.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(7, hole->first, "3.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "3.2.last");

	/* Bytes 8 through 64 arrive. */
	error = create_skb6_udp_frag(&tuple6, &skb4, 56, 72, true, true, 8, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb4, &full_skb), "verdict 4");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(2, &buffer->holes, "Hole count 4");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(0, hole->first, "4.1.first");
	success &= assert_equals_u16(0, hole->last, "4.1.last");
	hole = list_entry(hole->list_hook.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(8, hole->first, "4.2.first");
	success &= assert_equals_u16(INFINITY, hole->last, "4.2.last");

	/* Bytes 64 through 72 arrive.*/
	error = create_skb6_udp_frag(&tuple6, &skb5, 8, 72, true, false, 64, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb5, &full_skb), "verdict 5");
	success &= validate_database(1);

	buffer = list_entry(expire_list.prev, struct reassembly_buffer, list_hook);
	success &= assert_list_count(1, &buffer->holes, "Hole count 5");
	if (!success)
		return false;

	hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
	success &= assert_equals_u16(0, hole->first, "5.1.first");
	success &= assert_equals_u16(0, hole->last, "5.1.last");

	/* Bytes 0 through 8 arrive.*/
	error = create_skb6_udp_frag(&tuple6, &skb6, 0, 72, true, true, 0, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_CONTINUE, fragdb_handle6(skb6, &full_skb), "verdict 6");
	success &= validate_database(0);

	/* Validate the packet. */
	success &= validate_packet(full_skb, 6);

	/* Validate the fragments. */
	log_debug("Fragment 0-8");
	success &= validate_fragment(full_skb, true, true, 0);

	log_debug("Fragment 24-48");
	success &= validate_fragment(full_skb->next, false, true, 24);

	log_debug("Fragment 16-32");
	success &= validate_fragment(full_skb->next->next, false, true, 16);

	log_debug("Fragment 40-56");
	success &= validate_fragment(full_skb->next->next->next, false, true, 16);

	log_debug("Fragment 8-64");
	success &= validate_fragment(full_skb->next->next->next->next, false, true, 56);

	log_debug("Fragment 64-72");
	success &= validate_fragment(full_skb->next->next->next->next->next, false, true, 8);

	kfree_skb_queued(full_skb);
	return success;
}

static bool validate_list(struct reassembly_buffer_key *expected, int expected_count)
{
	struct reassembly_buffer *current_buffer;
	struct sk_buff *skb;
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	bool success = true;
	int c = 0;

	list_for_each_entry(current_buffer, &expire_list, list_hook) {
		if (!assert_true(c < expected_count, "List count"))
			return false;

		skb = current_buffer->skb;

		success &= assert_equals_int(expected[c].l3_proto, skb_l3_proto(skb), "l3-proto");
		success &= assert_equals_u8(L4PROTO_UDP, skb_l4_proto(skb), "proto");

		switch (expected[c].l3_proto) {
		case L3PROTO_IPV6:
			hdr6 = ipv6_hdr(skb);
			success &= assert_equals_ipv6(&expected[c].ipv6.src_addr, &hdr6->saddr, "src addr6");
			success &= assert_equals_ipv6(&expected[c].ipv6.dst_addr, &hdr6->daddr, "dst addr6");
			success &= assert_equals_be32(expected[c].ipv6.identification,
					skb_frag_hdr(skb)->identification, "frag id 6");
			break;
		case L3PROTO_IPV4:
			hdr4 = ip_hdr(skb);
			success &= assert_equals_be32(expected[c].ipv4.src_addr.s_addr, hdr4->saddr, "src4");
			success &= assert_equals_be32(expected[c].ipv4.dst_addr.s_addr, hdr4->daddr, "dst4");
			success &= assert_equals_be16(expected[c].ipv4.identification, hdr4->id, "frag id 4");
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
	struct tuple tuple13, tuple2; /* skbs 1 and 3 use tuple13. skb2 uses tuple2. */
	struct tuple tuple46, tuple5; /* skbs 4 and 6 use tuple46. skb5 uses tuple5. */
	struct reassembly_buffer_key expected_keys[6];
	struct reassembly_buffer *dummy_buffer;
	struct sk_buff *full_skb;
	bool success = true;
	int error;

	/* Pkt_DB(0) */
	error = init_ipv4_tuple(&tuple13, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_UDP);
	if (error)
		return false;
	/* Pkt_DB(1) */
	error = init_ipv4_tuple(&tuple2, "11.12.13.14", 1112, "14.13.12.11", 1413, L4PROTO_UDP);
	if (error)
		return false;
	/* Pkt_DB(2) */
	error = init_ipv6_tuple(&tuple46, "1::2", 1212, "3::4", 3434, L4PROTO_UDP);
	if (error)
		return false;
	/* Pkt_DB(3) */
	error = init_ipv6_tuple(&tuple5, "8::7", 8787, "6::5", 6565, L4PROTO_UDP);
	if (error)
		return false;

	expected_keys[0].l3_proto = L3PROTO_IPV4;
	expected_keys[0].ipv4.src_addr = tuple13.src.addr4.l3;
	expected_keys[0].ipv4.dst_addr = tuple13.dst.addr4.l3;
	expected_keys[0].ipv4.identification = cpu_to_be16(4321);
	expected_keys[0].l4_proto = IPPROTO_UDP;

	expected_keys[1].l3_proto = L3PROTO_IPV4;
	expected_keys[1].ipv4.src_addr = tuple2.src.addr4.l3;
	expected_keys[1].ipv4.dst_addr = tuple2.dst.addr4.l3;
	expected_keys[1].ipv4.identification = cpu_to_be16(4321);
	expected_keys[1].l4_proto = IPPROTO_UDP;

	expected_keys[2].l3_proto = L3PROTO_IPV6;
	expected_keys[2].ipv6.src_addr = tuple46.src.addr6.l3;
	expected_keys[2].ipv6.dst_addr = tuple46.dst.addr6.l3;
	expected_keys[2].ipv6.identification = cpu_to_be32(4321);
	expected_keys[2].l4_proto = NEXTHDR_UDP;

	expected_keys[3].l3_proto = L3PROTO_IPV6;
	expected_keys[3].ipv6.src_addr = tuple5.src.addr6.l3;
	expected_keys[3].ipv6.dst_addr = tuple5.dst.addr6.l3;
	expected_keys[3].ipv6.identification = cpu_to_be32(4321);
	expected_keys[3].l4_proto = NEXTHDR_UDP;

	/* Fragment 1.1 arrives (first fragment of packet 1) (IPv4). */
	error = create_skb4_udp_frag(&tuple13, &skb1, 100, 1000, false, true, 0, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb1, &full_skb), "1st verdict");

	success &= validate_database(1);
	success &= validate_list(&expected_keys[0], 1);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 1"); */
	clean_expired_buffers();
	success &= validate_database(1);
	success &= validate_list(&expected_keys[0], 1);

	/* Fragment 2.1 arrives (first fragment of packet 2) (IPv4). */
	error = create_skb4_udp_frag(&tuple2, &skb2, 100, 1000, false, true, 0, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb2, &full_skb), "2nd verdict");

	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2"); */
	clean_expired_buffers();
	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);

	/* Fragment 1.2 arrives (IPv4). */
	error = create_skb4_udp_frag(&tuple13, &skb3, 100, 1000, false, true, 108, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle4(skb3, &full_skb), "3rd verdict");

	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 2"); */
	clean_expired_buffers();
	success &= validate_database(2);
	success &= validate_list(&expected_keys[0], 2);

	/* Fragment 3.1 (IPv6) arrives. */
	error = create_skb6_udp_frag(&tuple46, &skb4, 100, 1000, true, true, 0, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb4, &full_skb), "4th verdict");

	success &= validate_database(3);
	success &= validate_list(&expected_keys[0], 3);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 4"); */
	clean_expired_buffers();
	success &= validate_database(3);
	success &= validate_list(&expected_keys[0], 3);

	/* Fragment 4.1 (IPv6) arrives. */
	error = create_skb6_udp_frag(&tuple5, &skb5, 100, 1000, true, true, 0, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb5, &full_skb), "5th verdict");

	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 5"); */
	clean_expired_buffers();
	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);

	/* Fragment 3.2 arrives (IPv6). */
	error = create_skb6_udp_frag(&tuple46, &skb6, 100, 1000, true, true, 108, 32);
	if (error)
		return false;
	success &= assert_equals_int(VER_STOLEN, fragdb_handle6(skb6, &full_skb), "6th verdict");

	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);
	/* success &= assert_range(1900, 2100, clean_expired_fragments(), "Timer 6"); */
	clean_expired_buffers();
	success &= validate_database(4);
	success &= validate_list(&expected_keys[0], 4);

	/* After 2 seconds, packet 1 should die. */
	dummy_buffer = container_of(expire_list.next, struct reassembly_buffer, list_hook);
	dummy_buffer->dying_time = jiffies - 1;
	dummy_buffer = container_of(dummy_buffer->list_hook.next, struct reassembly_buffer, list_hook);
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
	dummy_buffer = container_of(expire_list.next, struct reassembly_buffer, list_hook);
	dummy_buffer->dying_time = jiffies - 1;
	dummy_buffer = container_of(dummy_buffer->list_hook.next, struct reassembly_buffer, list_hook);
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

	if (is_error(fragdb_init()))
		return -EINVAL;

	CALL_TEST(test_no_fragments_4(), "Unfragmented IPv4 packet arrives");
	CALL_TEST(test_no_fragments_6(), "Unfragmented IPv6 packet arrives");
	CALL_TEST(test_ordered_fragments_4(), "3 ordered IPv4 fragments");
	CALL_TEST(test_ordered_fragments_6(), "3 ordered IPv6 fragments");
	CALL_TEST(test_disordered_fragments_4(), "3 disordered IPv4 fragments");
	CALL_TEST(test_disordered_fragments_6(), "3 disordered IPv6 fragments");
	CALL_TEST(test_timer(), "Timer test.");

	fragdb_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
