#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "translate_packet.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Translating the Packet module test.");

struct in6_addr dummies6[2];



#define PKT_LEN 100
bool test_simple(void)
{
	struct tuple tuple;
	struct packet pkt_in;
	struct packet pkt_out;
	struct fragment frag;
	struct sk_buff *skb;

	struct iphdr *hdr4;
	struct udphdr *udp_header;
	unsigned char *payload;

	enum verdict result;
	int i;

	// init the skb.
	skb = alloc_skb(100 + PKT_LEN + 100, GFP_ATOMIC);
	if (!skb) {
		log_warning("Could not allocate the skb.");
		return false;
	}

	skb_reserve(skb, 100);
	skb_put(skb, PKT_LEN);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(*hdr4));

	hdr4 = ip_hdr(skb);
	udp_header = udp_hdr(skb);
	payload = (unsigned char *) (udp_header + 1);

	hdr4->version = 4;
	hdr4->ihl = sizeof(*hdr4) / 4;
	hdr4->tos = 0;
	hdr4->tot_len = cpu_to_be16(PKT_LEN);
	hdr4->id = cpu_to_be16(1234);
	hdr4->frag_off = cpu_to_be16(IP_DF | 0x0000);
	hdr4->ttl = 5;
	hdr4->protocol = IPPROTO_UDP;
	hdr4->check = 0xFAFA;
	hdr4->saddr = cpu_to_be32(0x12345678);
	hdr4->daddr = cpu_to_be32(0xFEDCBA98);

	udp_header->source = cpu_to_be16(5883);
	udp_header->dest = cpu_to_be16(9215);
	udp_header->len = cpu_to_be16(PKT_LEN - sizeof(*hdr4));
	udp_header->check = cpu_to_be16(0xAFAF);

	for (i = 0; i < PKT_LEN - sizeof(*hdr4) - sizeof(*udp_header); i++)
		payload[i] = i;

	// init the fragment.
	frag_init(&frag);
	frag.skb = skb;

	frag.l3_hdr.proto = L3PROTO_IPV4;
	frag.l3_hdr.len = sizeof(*hdr4);
	frag.l3_hdr.ptr = hdr4;
	frag.l3_hdr.ptr_belongs_to_skb = true;

	frag.l4_hdr.proto = L3PROTO_IPV4;
	frag.l4_hdr.len = sizeof(*udp_header);
	frag.l4_hdr.ptr = udp_header;
	frag.l4_hdr.ptr_belongs_to_skb = true;

	frag.payload.len = PKT_LEN - sizeof(*hdr4) - sizeof(*udp_header);
	frag.payload.ptr = payload;
	frag.payload.ptr_belongs_to_skb = true;

	// init the packets.
	INIT_LIST_HEAD(&pkt_in.fragments);
	list_add(&frag.next, &pkt_in.fragments);

	INIT_LIST_HEAD(&pkt_out.fragments);

	// init the tuple.
	tuple.l3_proto = L3PROTO_IPV6;
	tuple.l3_proto = L4PROTO_UDP;
	tuple.src.addr.ipv6 = dummies6[0];
	tuple.src.l4_id = 1234;
	tuple.dst.addr.ipv6 = dummies6[1];
	tuple.dst.l4_id = 4321;

	// Call the function.
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE) {
		log_info("Result: %d", result);
		kfree_skb(skb);
		return false;
	}

	log_info("Yaaaaaaaaay.");
	kfree_skb(skb);
	return true;
}

int init_module(void)
{
	START_TESTS("Translating the Packet (IPv4 to IPv6)");

	if (str_to_addr6("1::1", &dummies6[0]) != 0)
		return -EINVAL;
	if (str_to_addr6("2::2", &dummies6[1]) != 0)
		return -EINVAL;

	translate_packet_init();
	CALL_TEST(test_simple(), "simple");
	translate_packet_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
