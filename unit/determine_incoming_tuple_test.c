#include <linux/module.h>
#include <linux/slab.h>

#include "nat64/unit/unit_test.h"
//#include "nat64/unit/skb_generator.h"
//#include "nat64/unit/validator.h"
//#include "nat64/unit/types.h"
//#include "nat64/comm/str_utils.h"
//#include "nat64/comm/constants.h"
//#include "nat64/mod/ipv6_hdr_iterator.h"

#define GENERATE_FOR_EACH true
#include "determine_incoming_tuple.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roberto Aceves");
MODULE_AUTHOR("Alberto Leiva");
MODULE_DESCRIPTION("Packet database test");

#define GOOD 0
static bool create_packet_fragmented_disordered(struct packet *pkt)
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
	error = create_skb_ipv4_udp_fragment(&pair4, &skb3, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb3);
	hdr4->frag_off = build_ipv4_frag_off_field(false, false, sizeof(struct udphdr) + 200);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= VER_STOLEN == pkt_from_skb(skb3, &pkt);

	/* Second packet arrives. */
	error = create_skb_ipv4_udp_fragment(&pair4, &skb2, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb2);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, sizeof(struct udphdr) + 100);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= VER_STOLEN == pkt_from_skb(skb2, &pkt);

	/* Third and final packet arrives. */
	error = create_skb_ipv4_udp(&pair4, &skb1, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb1);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= VER_CONTINUE == pkt_from_skb(skb1, &pkt);




	return success;
}





/**
 * Three things fragments arriving in disorder.
 */
static bool test_determine_in_tuple_ipv4(void)
{
	struct packet *pkt;
	struct fragment *frag;
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv4_pair pair13, pair2;
	struct iphdr *hdr4;
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



	success &= create_packet_fragmented_disordered(pkt);


	success &= determine_in_tuple(pkt, tuple);

	pkt_kfree(pkt, true);
	return success;
}

int init_module(void)
{
	START_TESTS("Determine incoming tuple");

	CALL_TEST(test_determine_in_tuple_ipv4(), "Determine incoming tuple of a 3 fragments IPv4 packet.");

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
