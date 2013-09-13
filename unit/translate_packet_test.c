#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "nat64/comm/str_utils.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/validator.h"
#include "nat64/unit/types.h"
#include "translate_packet.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("Translating the Packet module test.");


static struct in6_addr dummies6[2];
static struct in_addr dummies4[2];


static struct fragment *create_fragment_ipv4(int payload_len,
		int (*skb_create_fn)(struct ipv4_pair *, struct sk_buff **, u16), u16 df, u16 mf, u16 frag_off)
{
	struct fragment *frag;
	struct sk_buff *skb;
	struct ipv4_pair pair4;
	struct iphdr *hdr4;
	enum verdict result;

	/* init the skb. */
	pair4.remote.address = dummies4[0];
	pair4.remote.l4_id = 5644;
	pair4.local.address = dummies4[1];
	pair4.local.l4_id = 6721;
	if (skb_create_fn(&pair4, &skb, payload_len) != 0)
		return NULL;

	hdr4 = ip_hdr(skb);
	hdr4->frag_off = cpu_to_be16(df | mf | frag_off);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	/* init the fragment. */
	result = frag_create_ipv4(skb, &frag);
	if (!result) {
		log_warning("Could not allocate the fragment.");
		kfree_skb(skb);
		return NULL;
	}

	return frag;
}

static struct packet *create_pkt_ipv4(int payload_len,
		int (*skb_create_fn)(struct ipv4_pair *, struct sk_buff **, u16))
{
	struct fragment *frag;
	struct packet *pkt;

	frag = create_fragment_ipv4(payload_len, skb_create_fn, IP_DF, 0, 0);
	if (!frag)
		return NULL;

	pkt = pkt_create_ipv4(frag);
	if (!pkt)
		frag_kfree(frag);

	return pkt;
}

static struct fragment *create_fragment_ipv6(int payload_len,
		int (*skb_create_fn)(struct ipv6_pair *, struct sk_buff **, u16), u16 mf, u16 frag_off)
{
	struct fragment *frag;
	struct sk_buff *skb;
	struct ipv6_pair pair6;
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag_header;
	enum verdict result;

	/* init the skb. */
	pair6.remote.address = dummies6[0];
	pair6.remote.l4_id = 5644;
	pair6.local.address = dummies6[1];
	pair6.local.l4_id = 6721;
	if (skb_create_fn(&pair6, &skb, payload_len) != 0)
		return NULL;

	hdr6 = ipv6_hdr(skb);
	if (hdr6->nexthdr == NEXTHDR_FRAGMENT) {
		frag_header = (struct frag_hdr *) (hdr6 + 1);
		frag_header->frag_off = build_ipv6_frag_off_field(frag_off, mf);
	}

	/* init the fragment. */
	result = frag_create_ipv6(skb, &frag);
	if (!result) {
		log_warning("Could not allocate the fragment.");
		kfree_skb(skb);
		return NULL;
	}

	return frag;
}

static struct packet *create_pkt_ipv6(int payload_len,
		int (*skb_create_fn)(struct ipv6_pair *, struct sk_buff **, u16))
{
	struct fragment *frag;
	struct packet *pkt;

	frag = create_fragment_ipv6(payload_len, skb_create_fn, 0, 0);
	if (!frag)
		return NULL;

	pkt = pkt_create_ipv6(frag);
	if (!pkt)
		frag_kfree(frag);

	return pkt;
}

static bool create_tuple_ipv6(struct tuple *tuple, u_int8_t l4proto)
{
	tuple->l3_proto = L3PROTO_IPV6;
	tuple->l4_proto = l4proto;
	tuple->src.addr.ipv6 = dummies6[0];
	tuple->src.l4_id = 1234;
	tuple->dst.addr.ipv6 = dummies6[1];
	tuple->dst.l4_id = 4321;

	return true;
}

static bool create_tuple_ipv4(struct tuple *tuple, u_int8_t l4proto)
{
	tuple->l3_proto = L3PROTO_IPV4;
	tuple->l4_proto = l4proto;
	tuple->src.addr.ipv4 = dummies4[0];
	tuple->src.l4_id = 1234;
	tuple->dst.addr.ipv4 = dummies4[1];
	tuple->dst.l4_id = 4321;

	return true;
}

static bool test_post_tcp_csum_6to4(void)
{
	struct sk_buff *skb_in = NULL, *skb_out = NULL;
	struct fragment *frag_in = NULL, *frag_out = NULL;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple;
	__sum16 expected_csum;

	struct tcphdr *hdr_tcp;

	if (init_pair6(&pair6, "1::4", 1234, "6::9", 2345) != 0)
		return false;
	if (init_pair4(&pair4, "1.2.3.4", 1234, "6.7.8.9", 2345) != 0)
		return false;

	/* We're assuming both of these will have the same layer-4 headers and payloads. */
	if (create_skb_ipv6_tcp(&pair6, &skb_in, 100) != 0)
		goto error;
	if (create_skb_ipv4_tcp(&pair4, &skb_out, 100) != 0)
		goto error;

	if (frag_create_ipv6(skb_in, &frag_in) != VER_CONTINUE)
		goto error;
	if (frag_create_ipv4(skb_out, &frag_out) != VER_CONTINUE)
		goto error;

	hdr_tcp = frag_get_tcp_hdr(frag_out);
	expected_csum = hdr_tcp->check;

	tuple.src.l4_id = 1234;
	tuple.dst.l4_id = 2345;

	post_tcp_ipv4(&tuple, frag_in, frag_out);

	return assert_equals_csum(expected_csum, hdr_tcp->check, "Checksum");

error:
	if (frag_in)
		frag_kfree(frag_in);
	else
		kfree_skb(skb_in);
	if (frag_out)
		frag_kfree(frag_out);
	else
		kfree_skb(skb_out);
	return false;
}

static bool test_post_udp_csum_6to4(void)
{
	struct sk_buff *skb_in = NULL, *skb_out = NULL;
	struct fragment *frag_in = NULL, *frag_out = NULL;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple;
	__sum16 expected_csum;

	struct udphdr *hdr_udp;

	if (init_pair6(&pair6, "1::4", 1234, "6::9", 2345) != 0)
		return false;
	if (init_pair4(&pair4, "1.2.3.4", 1234, "6.7.8.9", 2345) != 0)
		return false;

	/* We're assuming both of these will have the same layer-4 headers and payloads. */
	if (create_skb_ipv6_udp(&pair6, &skb_in, 100) != 0)
		goto error;
	if (create_skb_ipv4_udp(&pair4, &skb_out, 100) != 0)
		goto error;

	if (frag_create_ipv6(skb_in, &frag_in) != VER_CONTINUE)
		goto error;
	if (frag_create_ipv4(skb_out, &frag_out) != VER_CONTINUE)
		goto error;

	hdr_udp = frag_get_udp_hdr(frag_out);
	expected_csum = hdr_udp->check;

	tuple.src.l4_id = 1234;
	tuple.dst.l4_id = 2345;

	post_udp_ipv4(&tuple, frag_in, frag_out);

	return assert_equals_csum(expected_csum, hdr_udp->check, "Checksum");

error:
	if (frag_in)
		frag_kfree(frag_in);
	else
		kfree_skb(skb_in);
	if (frag_out)
		frag_kfree(frag_out);
	else
		kfree_skb(skb_out);
	return false;
}

static bool test_update_csum_4to6(void)
{
	unsigned char in_pkt[256];
	unsigned char out_pkt[256];

	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct tcphdr *hdr_tcp4;
	struct tcphdr *hdr_tcp6;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;

	int datagram_len = sizeof(*hdr_tcp4) + 100;
	__sum16 expected_csum, actual_csum;

	if (init_pair4(&pair4, "1.2.3.4", 5678, "9.10.11.12", 1314) != 0)
		return false;
	if (init_pair6(&pair6, "15::16", 1718, "19::20", 2122) != 0)
		return false;

	hdr4 = (struct iphdr *) &in_pkt[0];
	hdr_tcp4 = (struct tcphdr *) (hdr4 + 1);
	if (init_ipv4_hdr(hdr4, datagram_len, IPPROTO_TCP, &pair4) != 0)
		return false;
	if (init_tcp_hdr(hdr_tcp4, ETH_P_IP, datagram_len, &pair4) != 0)
		return false;
	if (init_payload_normal(hdr_tcp4 + 1, 100) != 0)
		return false;
	if (ipv4_tcp_post(hdr_tcp4, datagram_len, &pair4) != 0)
		return false;

	hdr6 = (struct ipv6hdr *) &out_pkt[0];
	hdr_tcp6 = (struct tcphdr *) (hdr6 + 1);
	if (init_ipv6_hdr(hdr6, datagram_len, NEXTHDR_TCP, &pair6) != 0)
		return false;
	if (init_tcp_hdr(hdr_tcp6, ETH_P_IPV6, datagram_len, &pair6) != 0)
		return false;
	if (init_payload_normal(hdr_tcp6 + 1, 100) != 0)
		return false;
	if (ipv6_tcp_post(hdr_tcp6, datagram_len, &pair6) != 0)
		return false;

	expected_csum = hdr_tcp6->check;
	actual_csum = update_csum_4to6(hdr_tcp4->check,
			hdr4, cpu_to_be16(5678), cpu_to_be16(1314),
			hdr6, cpu_to_be16(1718), cpu_to_be16(2122));

	return assert_equals_csum(expected_csum, actual_csum, "Checksums");
}

static bool test_function_has_unexpired_src_route(void)
{
	struct iphdr *hdr = kmalloc(60, GFP_ATOMIC); /* 60 is the max value allowed by hdr.ihl. */
	unsigned char *options;
	bool success = true;

	if (!hdr) {
		log_warning("Can't allocate a test header.");
		return false;
	}
	options = (unsigned char *) (hdr + 1);

	hdr->ihl = 5; /* min legal value. */
	success &= assert_false(has_unexpired_src_route(hdr), "No options");

	hdr->ihl = 6;
	options[0] = IPOPT_SID;
	options[1] = 4;
	options[2] = 0xAB;
	options[3] = 0xCD;
	success = assert_false(has_unexpired_src_route(hdr), "No source route option, simple");

	hdr->ihl = 9;
	options[0] = IPOPT_RR; /* Record route option */
	options[1] = 11;
	options[2] = 8;
	options[3] = 0x12;
	options[4] = 0x34;
	options[5] = 0x56;
	options[6] = 0x78;
	options[7] = 0x00;
	options[8] = 0x00;
	options[9] = 0x00;
	options[10] = 0x00;
	options[11] = IPOPT_NOOP; /* No operation option. */
	options[12] = IPOPT_NOOP; /* No operation option. */
	options[13] = IPOPT_END; /* End of options list option. */
	/* Leave the rest as garbage. */
	success &= assert_false(has_unexpired_src_route(hdr), "No source option, multiple options");

	hdr->ihl = 9;
	options[0] = IPOPT_LSRR;
	options[1] = 15;
	options[2] = 16;
	options[3] = 0x11; /* First address */
	options[4] = 0x11;
	options[5] = 0x11;
	options[6] = 0x11;
	options[7] = 0x22; /* Second address */
	options[8] = 0x22;
	options[9] = 0x22;
	options[10] = 0x22;
	options[11] = 0x33; /* Third address */
	options[12] = 0x33;
	options[13] = 0x33;
	options[14] = 0x33;
	options[15] = IPOPT_END;
	success &= assert_false(has_unexpired_src_route(hdr), "Expired source route");

	options[2] = 4;
	success &= assert_true(has_unexpired_src_route(hdr), "Unexpired source route, first address");
	options[2] = 8;
	success &= assert_true(has_unexpired_src_route(hdr), "Unexpired source route, second address");
	options[2] = 12;
	success &= assert_true(has_unexpired_src_route(hdr), "Unexpired source route, third address");

	hdr->ihl = 11;
	options[0] = IPOPT_NOOP;
	options[1] = IPOPT_SID;
	options[2] = 4;
	options[3] = 0xAB;
	options[4] = 0xCD;
	options[5] = IPOPT_LSRR;
	options[6] = 15;
	options[7] = 16;
	options[8] = 0x11; /* First address */
	options[9] = 0x11;
	options[10] = 0x11;
	options[11] = 0x11;
	options[12] = 0x22; /* Second address */
	options[13] = 0x22;
	options[14] = 0x22;
	options[15] = 0x22;
	options[16] = 0x33; /* Third address */
	options[17] = 0x33;
	options[18] = 0x33;
	options[19] = 0x33;
	options[20] = IPOPT_SID;
	options[21] = 4;
	options[22] = 0xAB;
	options[23] = 0xCD;
	success &= assert_false(has_unexpired_src_route(hdr), "Expired source route, multiple opts");

	options[7] = 4;
	success &= assert_true(has_unexpired_src_route(hdr), "Unexpired src route, multiple opts (1)");
	options[7] = 8;
	success &= assert_true(has_unexpired_src_route(hdr), "Unexpired src route, multiple opts (2)");
	options[7] = 12;
	success &= assert_true(has_unexpired_src_route(hdr), "Unexpired src route, multiple opts (3)");

	kfree(hdr);
	return success;
}

static bool test_function_build_id_field(void)
{
	struct iphdr hdr;
	bool success = true;

	hdr.id = cpu_to_be16(1234);
	success &= assert_equals_u32(cpu_to_be32(1234), build_id_field(&hdr), "Simple");

	return success;
}

#define min_mtu(packet, in, out, len) be32_to_cpu(icmp6_minimum_mtu(packet, in, out, len))
static bool test_function_icmp6_minimum_mtu(void)
{
	int i;
	bool success = true;

	__u16 plateaus[] = { 1400, 1200, 600 };

	bool old_lower_mtu_fail = config.lower_mtu_fail;
	__u16 *old_plateaus = config.mtu_plateaus;
	__u16 old_plateaus_count = config.mtu_plateau_count;

	config.lower_mtu_fail = false;
	config.mtu_plateaus = plateaus;
	config.mtu_plateau_count = ARRAY_SIZE(plateaus);

	/* Test the bare minimum functionality. */
	success &= assert_equals_u32(1, min_mtu(1, 2, 2, 0), "No hacks, min is packet");
	success &= assert_equals_u32(1, min_mtu(2, 1, 2, 0), "No hacks, min is in");
	success &= assert_equals_u32(1, min_mtu(2, 2, 1, 0), "No hacks, min is out");

	if (!success)
		goto revert;

	/* Test hack 1: MTU is overriden if some router set is as zero. */
	for (i = 1500; i > 1400; --i)
		success &= assert_equals_u32(1400, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 1400; i > 1200; --i)
		success &= assert_equals_u32(1200, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 1200; i > 600; --i)
		success &= assert_equals_u32(600, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 600; i > 0; --i)
		success &= assert_equals_u32(0, min_mtu(0, 1600, 1600, i), "Override packet MTU");

	success &= assert_equals_u32(1, min_mtu(0, 1, 2, 1000), "Override packet MTU, min is in");
	success &= assert_equals_u32(1, min_mtu(0, 2, 1, 1000), "Override packet MTU, min is out");

	if (!success)
		goto revert;

	/* Test hack 2: User wants us to try to improve the failure rate. */
	config.lower_mtu_fail = true;

	success &= assert_equals_u32(1280, min_mtu(1, 2, 2, 0), "Improve rate, min is packet");
	success &= assert_equals_u32(1280, min_mtu(2, 1, 2, 0), "Improve rate, min is in");
	success &= assert_equals_u32(1280, min_mtu(2, 2, 1, 0), "Improve rate, min is out");

	success &= assert_equals_u32(1300, min_mtu(1300, 1400, 1400, 0), "Fail improve rate, packet");
	success &= assert_equals_u32(1300, min_mtu(1400, 1300, 1400, 0), "Fail improve rate, in");
	success &= assert_equals_u32(1300, min_mtu(1400, 1400, 1300, 0), "Fail improve rate, out");

	if (!success)
		goto revert;

	/* Test both hacks at the same time. */
	success &= assert_equals_u32(1280, min_mtu(0, 700, 700, 1000), "2 hacks, override packet");
	success &= assert_equals_u32(1280, min_mtu(0, 1, 2, 1000), "2 hacks, override in");
	success &= assert_equals_u32(1280, min_mtu(0, 2, 1, 1000), "2 hacks, override out");

	success &= assert_equals_u32(1400, min_mtu(0, 1500, 1500, 1401), "2 hacks, packet/not 1280");
	success &= assert_equals_u32(1400, min_mtu(0, 1400, 1500, 1501), "2 hacks, in/not 1280");
	success &= assert_equals_u32(1400, min_mtu(0, 1500, 1400, 1501), "2 hacks, out/not 1280");

	/* Fall through. */
revert:
	config.lower_mtu_fail = old_lower_mtu_fail;
	config.mtu_plateaus = old_plateaus;
	config.mtu_plateau_count = old_plateaus_count;
	return success;
}
#undef min_mtu

static bool test_function_icmp4_to_icmp6_param_prob(void)
{
	struct icmphdr hdr4;
	struct icmp6hdr hdr6;
	bool success = true;

	hdr4.type = ICMP_PARAMETERPROB;
	hdr4.code = ICMP_PTR_INDICATES_ERROR;
	hdr4.icmp4_unused = cpu_to_be32(0x08000000);
	success &= assert_true(icmp4_to_icmp6_param_prob(&hdr4, &hdr6), "func result 1");
	success &= assert_equals_u8(ICMPV6_HDR_FIELD, hdr6.icmp6_code, "code");
	success &= assert_equals_u8(7, be32_to_cpu(hdr6.icmp6_pointer), "pointer");

	hdr4.icmp4_unused = cpu_to_be32(0x05000000);
	success &= assert_false(icmp4_to_icmp6_param_prob(&hdr4, &hdr6), "func result 2");

	return success;
}

static bool test_function_build_tos_field(void)
{
	__u8 ipv6_header[4]; /* We don't really need the rest of the bytes. */
	bool success = true;

	/*
	 * version: 2 (Yes, it's not 6. Doesn't matter.)
	 * traffic class: ce
	 * flow label: 3c3e0
	 */
	ipv6_header[0] = 0x2c;
	ipv6_header[1] = 0xe3;
	ipv6_header[2] = 0xc3;
	ipv6_header[3] = 0xe0;
	success &= assert_equals_u8(0xce, build_tos_field((struct ipv6hdr *) ipv6_header), "Simple");

	return success;
}

static bool test_function_generate_ipv4_id_nofrag(void)
{
	struct ipv6hdr hdr;
	__be16 attempt_1, attempt_2, attempt_3;
	bool success = true;

	hdr.payload_len = cpu_to_be16(4); /* packet length is 44. */
	success &= assert_equals_u16(0, generate_ipv4_id_nofrag(&hdr), "Length < 88 bytes");

	hdr.payload_len = cpu_to_be16(48); /* packet length is 88. */
	success &= assert_equals_u16(0, generate_ipv4_id_nofrag(&hdr), "Length = 88 bytes");

	hdr.payload_len = cpu_to_be16(500); /* packet length is 540. */
	attempt_1 = generate_ipv4_id_nofrag(&hdr);
	attempt_2 = generate_ipv4_id_nofrag(&hdr);
	attempt_3 = generate_ipv4_id_nofrag(&hdr);
	/*
	 * At least one of the attempts should be nonzero,
	 * otherwise the random would be sucking major ****.
	 */
	success &= assert_not_equals_u16(0, (attempt_1 | attempt_2 | attempt_3), "88 < Len < 1280");

	hdr.payload_len = cpu_to_be16(1240); /* packet length is 1280. */
	attempt_1 = generate_ipv4_id_nofrag(&hdr);
	attempt_2 = generate_ipv4_id_nofrag(&hdr);
	attempt_3 = generate_ipv4_id_nofrag(&hdr);
	success &= assert_not_equals_u16(0, (attempt_1 | attempt_2 | attempt_3), "Len = 1280");

	hdr.payload_len = cpu_to_be16(4000); /* packet length is 4040. */
	success &= assert_equals_u16(0, generate_ipv4_id_nofrag(&hdr), "Len > 1280");

	return success;
}

static bool test_function_generate_df_flag(void)
{
	struct ipv6hdr hdr;
	bool success = true;

	hdr.payload_len = cpu_to_be16(4); /* packet length is 44. */
	success &= assert_equals_u16(1, generate_df_flag(&hdr), "Length < 88 bytes");

	hdr.payload_len = cpu_to_be16(48); /* packet length is 88. */
	success &= assert_equals_u16(1, generate_df_flag(&hdr), "Length = 88 bytes");

	hdr.payload_len = cpu_to_be16(500); /* packet length is 540. */
	success &= assert_equals_u16(0, generate_df_flag(&hdr), "88 < Len < 1280");

	hdr.payload_len = cpu_to_be16(1240); /* packet length is 1280. */
	success &= assert_equals_u16(0, generate_df_flag(&hdr), "Len = 1280");

	hdr.payload_len = cpu_to_be16(4000); /* packet length is 4040. */
	success &= assert_equals_u16(1, generate_df_flag(&hdr), "Len > 1280");

	return success;
}

/**
 * By the way. This test kind of looks like it should test more combinations of headers.
 * But that'd be testing the header iterator, not the build_protocol_field() function.
 * Please look elsewhere for that.
 */
static bool test_function_build_protocol_field(void)
{
	struct ipv6hdr *ip6_hdr;
	struct ipv6_opt_hdr *hop_by_hop_hdr;
	struct ipv6_opt_hdr *routing_hdr;
	struct ipv6_opt_hdr *dest_options_hdr;
	struct icmp6hdr *icmp6_hdr;

	ip6_hdr = kmalloc(sizeof(*ip6_hdr) + 8 + 16 + 24 + sizeof(struct tcphdr), GFP_ATOMIC);
	if (!ip6_hdr) {
		log_warning("Could not allocate a test packet.");
		goto failure;
	}

	/* Just ICMP. */
	ip6_hdr->nexthdr = NEXTHDR_ICMP;
	ip6_hdr->payload_len = cpu_to_be16(sizeof(*icmp6_hdr));
	if (!assert_equals_u8(IPPROTO_ICMP, build_protocol_field(ip6_hdr), "Just ICMP"))
		goto failure;

	/* Skippable headers then ICMP. */
	ip6_hdr->nexthdr = NEXTHDR_HOP;
	ip6_hdr->payload_len = cpu_to_be16(8 + 16 + 24 + sizeof(*icmp6_hdr));

	hop_by_hop_hdr = (struct ipv6_opt_hdr *) (ip6_hdr + 1);
	hop_by_hop_hdr->nexthdr = NEXTHDR_ROUTING;
	hop_by_hop_hdr->hdrlen = 0; /* the hdrlen field does not include the first 8 octets. */

	routing_hdr = (struct ipv6_opt_hdr *) (((unsigned char *) hop_by_hop_hdr) + 8);
	routing_hdr->nexthdr = NEXTHDR_DEST;
	routing_hdr->hdrlen = 1;

	dest_options_hdr = (struct ipv6_opt_hdr *) (((unsigned char *) routing_hdr) + 16);
	dest_options_hdr->nexthdr = NEXTHDR_ICMP;
	dest_options_hdr->hdrlen = 2;

	if (!assert_equals_u8(IPPROTO_ICMP, build_protocol_field(ip6_hdr), "Skippable then ICMP"))
		goto failure;

	/* Skippable headers then something else */
	dest_options_hdr->nexthdr = NEXTHDR_TCP;
	ip6_hdr->payload_len = cpu_to_be16(8 + 16 + 24 + sizeof(struct tcphdr));
	if (!assert_equals_u8(IPPROTO_TCP, build_protocol_field(ip6_hdr), "Skippable then TCP"))
		goto failure;

	kfree(ip6_hdr);
	return true;

failure:
	kfree(ip6_hdr);
	return false;
}

static bool test_function_has_nonzero_segments_left(void)
{
	struct ipv6hdr *ip6_hdr;
	struct ipv6_rt_hdr *routing_hdr;
	struct frag_hdr *fragment_hdr;
	__u32 offset;

	bool success = true;

	ip6_hdr = kmalloc(sizeof(*ip6_hdr) + sizeof(*fragment_hdr) + sizeof(*routing_hdr), GFP_ATOMIC);
	if (!ip6_hdr) {
		log_warning("Could not allocate a test packet.");
		return false;
	}
	ip6_hdr->payload_len = cpu_to_be16(sizeof(*fragment_hdr) + sizeof(*routing_hdr));

	/* No extension headers. */
	ip6_hdr->nexthdr = NEXTHDR_TCP;
	success &= assert_false(has_nonzero_segments_left(ip6_hdr, &offset), "No extension headers");

	if (!success)
		goto end;

	/* Routing header with nonzero segments left. */
	ip6_hdr->nexthdr = NEXTHDR_ROUTING;
	routing_hdr = (struct ipv6_rt_hdr *) (ip6_hdr + 1);
	routing_hdr->segments_left = 12;
	success &= assert_true(has_nonzero_segments_left(ip6_hdr, &offset), "Nonzero left - result");
	success &= assert_equals_u32(40 + 3, offset, "Nonzero left - offset");

	if (!success)
		goto end;

	/* Routing header with zero segments left. */
	routing_hdr->segments_left = 0;
	success &= assert_false(has_nonzero_segments_left(ip6_hdr, &offset), "Zero left");

	if (!success)
		goto end;

	/*
	 * Fragment header, then routing header with nonzero segments left
	 * (further test the out parameter).
	 */
	ip6_hdr->nexthdr = NEXTHDR_FRAGMENT;
	fragment_hdr = (struct frag_hdr *) (ip6_hdr + 1);
	fragment_hdr->nexthdr = NEXTHDR_ROUTING;
	routing_hdr = (struct ipv6_rt_hdr *) (fragment_hdr + 1);
	routing_hdr->segments_left = 24;
	success &= assert_true(has_nonzero_segments_left(ip6_hdr, &offset), "Two headers - result");
	success &= assert_equals_u32(40 + 8 + 3, offset, "Two headers - offset");

	/* Fall through. */
end:
	kfree(ip6_hdr);
	return success;
}

static bool test_function_generate_ipv4_id_dofrag(void)
{
	struct frag_hdr fragment_hdr;
	bool success = true;

	fragment_hdr.identification = 0;
	success &= assert_equals_u16(0, be16_to_cpu(generate_ipv4_id_dofrag(&fragment_hdr)),
			"Simplest id");

	fragment_hdr.identification = cpu_to_be32(0x0000abcd);
	success &= assert_equals_u16(0xabcd, be16_to_cpu(generate_ipv4_id_dofrag(&fragment_hdr)),
			"No overflow");

	fragment_hdr.identification = cpu_to_be32(0x12345678);
	success &= assert_equals_u16(0x5678, be16_to_cpu(generate_ipv4_id_dofrag(&fragment_hdr)),
			"Overflow");

	return success;
}

static bool test_function_icmp4_minimum_mtu(void)
{
	bool success = true;

	success &= assert_equals_u16(2, be16_to_cpu(icmp4_minimum_mtu(2, 4, 6)), "First is min");
	success &= assert_equals_u16(8, be16_to_cpu(icmp4_minimum_mtu(10, 8, 12)), "Second is min");
	success &= assert_equals_u16(14, be16_to_cpu(icmp4_minimum_mtu(16, 18, 14)), "Third is min");

	return success;
}

static bool validate_pkt_ipv6_udp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr)))
		return false;
	if (!validate_frag_udp(frag))
		return false;
	if (!validate_frag_payload(frag, 100))
		return false;

	/* Validate the skb */
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), frag->l4_hdr.len + frag->payload.len,
			NEXTHDR_UDP, tuple))
		return false;
	if (!validate_udp_hdr(frag_get_udp_hdr(frag), 100, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), 100, 0))
		return false;

	return true;
}

static bool test_simple_4to6_udp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	if (!create_tuple_ipv6(&tuple, L4PROTO_UDP))
		return false;
	pkt_in = create_pkt_ipv4(100, create_skb_ipv4_udp);
	if (!pkt_in)
		return false;
	INIT_LIST_HEAD(&pkt_out.fragments);

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_ipv6_udp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_ipv6_tcp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr)))
		return false;
	if (!validate_frag_tcp(frag))
		return false;
	if (!validate_frag_payload(frag, 100))
		return false;

	/* Validate the skb */
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), frag->l4_hdr.len + frag->payload.len,
			NEXTHDR_TCP, tuple))
		return false;
	if (!validate_tcp_hdr(frag_get_tcp_hdr(frag), tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), 100, 0))
		return false;

	return true;
}

static bool test_simple_4to6_tcp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv6(&tuple, L4PROTO_TCP))
		return false;
	pkt_in = create_pkt_ipv4(100, create_skb_ipv4_tcp);
	if (!pkt_in)
		return false;

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_ipv6_tcp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_ipv6_icmp_info(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr)))
		return false;
	if (!validate_frag_icmp6(frag))
		return false;
	if (!validate_frag_payload(frag, 100))
		return false;

	/* Validate the skb */
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), frag->l4_hdr.len + frag->payload.len,
			NEXTHDR_ICMP, tuple))
		return false;
	if (!validate_icmp6_hdr(frag_get_icmp6_hdr(frag), 5644, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), 100, 0))
		return false;

	return true;
}

static bool test_simple_4to6_icmp_info(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv6(&tuple, L4PROTO_ICMP))
		return false;
	pkt_in = create_pkt_ipv4(100, create_skb_ipv4_icmp_info);
	if (!pkt_in)
		return false;

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_ipv6_icmp_info(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_ipv6_icmp_error(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr)))
		return false;
	if (!validate_frag_icmp6(frag))
		return false;
	if (!validate_frag_payload(frag, 120))
		return false;

	/* Validate the skb */
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), frag->l4_hdr.len + frag->payload.len,
			NEXTHDR_ICMP, tuple))
		return false;
	if (!validate_icmp6_hdr_error(frag_get_icmp6_hdr(frag)))
		return false;
	if (!validate_inner_pkt_ipv6(frag_get_payload(frag), 120))
		return false;

	return true;
}

static bool test_simple_4to6_icmp_error(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	if (!create_tuple_ipv6(&tuple, L4PROTO_ICMP))
		return false;
	pkt_in = create_pkt_ipv4(100, create_skb_ipv4_icmp_error);
	if (!pkt_in)
		return false;
	INIT_LIST_HEAD(&pkt_out.fragments);

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	/* The 20 extra bytes come from the difference between the IPv6 header and the IPv4 one. */
	if (!validate_pkt_ipv6_icmp_error(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_ipv4_udp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_udp(frag))
		return false;
	if (!validate_frag_payload(frag, 100))
		return false;

	/* Validate the skb */
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct udphdr) + 100,
			0, IP_DF, 0, 0, IPPROTO_UDP, tuple))
		return false;
	if (!validate_udp_hdr(frag_get_udp_hdr(frag), 100, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), 100, 0))
		return false;

	return true;
}

static bool test_simple_6to4_udp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv4(&tuple, L4PROTO_UDP))
		return false;

	pkt_in = create_pkt_ipv6(100, create_skb_ipv6_udp);
	if (!pkt_in)
		return false;

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_ipv4_udp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_ipv4_tcp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_tcp(frag))
		return false;
	if (!validate_frag_payload(frag, 100))
		return false;

	/* Validate the skb */
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct tcphdr) + 100,
			0, IP_DF, 0, 0, IPPROTO_TCP, tuple))
		return false;
	if (!validate_tcp_hdr(frag_get_tcp_hdr(frag), tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), 100, 0))
		return false;

	return true;
}

static bool test_simple_6to4_tcp(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	INIT_LIST_HEAD(&pkt_out.fragments);

	if (!create_tuple_ipv4(&tuple, L4PROTO_TCP))
		return false;
	pkt_in = create_pkt_ipv6(100, create_skb_ipv6_tcp);
	if (!pkt_in)
		return false;

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_ipv4_tcp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_ipv4_icmp_info(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_icmp4(frag))
		return false;
	if (!validate_frag_payload(frag, 100))
		return false;

	/* Validate the skb */
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct icmphdr) + 100,
			0, IP_DF, 0, 0, IPPROTO_ICMP, tuple))
		return false;
	if (!validate_icmp4_hdr(frag_get_icmp4_hdr(frag), 5644, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), 100, 0))
		return false;

	return true;
}

static bool test_simple_6to4_icmp_info(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	if (!create_tuple_ipv4(&tuple, L4PROTO_ICMP))
		return false;
	pkt_in = create_pkt_ipv6(100, create_skb_ipv6_icmp_info);
	if (!pkt_in)
		return false;
	INIT_LIST_HEAD(&pkt_out.fragments);

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_ipv4_icmp_info(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_ipv4_icmp_error(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	/* Validate the fragment */
	if (!validate_fragment_count(pkt, 1))
		return false;

	frag = container_of(pkt->fragments.next, struct fragment, next);

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_icmp4(frag))
		return false;
	if (!validate_frag_payload(frag, 80))
		return false;

	/* Validate the skb */
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct icmphdr) + 80,
			0, IP_DF, 0, 0, IPPROTO_ICMP, tuple))
		return false;
	if (!validate_icmp4_hdr_error(frag_get_icmp4_hdr(frag)))
		return false;
	if (!validate_inner_pkt_ipv4(frag_get_payload(frag), 80))
		return false;

	return true;
}

static bool test_simple_6to4_icmp_error(void)
{
	struct packet *pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;

	/* Init */
	if (!create_tuple_ipv4(&tuple, L4PROTO_ICMP))
		return false;
	pkt_in = create_pkt_ipv6(100, create_skb_ipv6_icmp_error);
	if (!pkt_in)
		return false;
	INIT_LIST_HEAD(&pkt_out.fragments);

	/* Call the function */
	result = translating_the_packet(&tuple, pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	/* The 20 missing bytes come from the difference between the IPv6 header and the IPv4 one. */
	if (!validate_pkt_ipv4_icmp_error(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(pkt_in, true);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_multiple_4to6_udp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;
	int payload_len;
	u16 offset;

	if (!validate_fragment_count(pkt, 3))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	offset = 0;
	payload_len = 1280 - sizeof(struct ipv6hdr) - sizeof(struct frag_hdr) - sizeof(struct udphdr);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_udp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), 1280 - sizeof(struct ipv6hdr), NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, IP6_MF, NEXTHDR_UDP))
		return false;
	if (!validate_udp_hdr(frag_get_udp_hdr(frag), 2000, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = 1232;
	payload_len = 776;

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the second skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), sizeof(struct frag_hdr) + payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, IP6_MF, NEXTHDR_UDP))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset - sizeof(struct udphdr)))
		return false;

	log_debug("Validating the third fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = 2008;
	payload_len = 100;

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the third skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), sizeof(struct frag_hdr) + payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, 0, NEXTHDR_UDP))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool test_multiple_4to6_udp(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	/* Init */
	INIT_LIST_HEAD(&pkt_in.fragments);
	INIT_LIST_HEAD(&pkt_out.fragments);
	if (!create_tuple_ipv6(&tuple, L4PROTO_UDP))
		return false;

	/*
	 * Two incoming fragments arriving in the correct order.
	 * The first one will be refragmented.
	 */
	frag = create_fragment_ipv4(2000, create_skb_ipv4_udp, 0, IP_MF, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	frag = create_fragment_ipv4(100, create_skb_ipv4_udp_fragment, 0, 0, 2008);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	/* Call the function */
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_multiple_4to6_udp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_fragment(struct fragment *frag, bool is_first, bool is_last, u16 offset,
		u16 payload_offset, u16 payload_len, struct tuple *tuple)
{
	u16 mf = is_last ? 0 : IP6_MF;
	u16 hdr_payload_len = sizeof(struct frag_hdr) + (is_first ? sizeof(struct tcphdr) : 0) + payload_len;

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (is_first) {
		if (!validate_frag_tcp(frag))
			return false;
	} else {
		if (!validate_frag_empty_l4(frag))
			return false;
	}
	if (!validate_frag_payload(frag, payload_len))
		return false;

	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), hdr_payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, mf, NEXTHDR_TCP))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, payload_offset))
		return false;

	return true;
}

static bool validate_pkt_multiple_4to6_tcp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;

	if (!validate_fragment_count(pkt, 6))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	if (!validate_fragment(frag, false, false, 3020, 0, 1232, tuple))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	if (!validate_fragment(frag, false, false, 4252, 1232, 1232, tuple))
		return false;

	log_debug("Validating the third fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	if (!validate_fragment(frag, false, true, 5484, 2464, 36, tuple))
		return false;

	log_debug("Validating the fourth fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	if (!validate_fragment(frag, true, false, 0, 0, 1212, tuple))
		return false;

	log_debug("Validating the fifth fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	if (!validate_fragment(frag, false, false, 1232, 1212, 1232, tuple))
		return false;

	log_debug("Validating the fifth fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	if (!validate_fragment(frag, false, false, 2464, 2444, 556, tuple))
		return false;

	return true;
}

static bool test_multiple_4to6_tcp(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	/* Init */
	INIT_LIST_HEAD(&pkt_in.fragments);
	INIT_LIST_HEAD(&pkt_out.fragments);
	if (!create_tuple_ipv6(&tuple, L4PROTO_TCP))
		return false;

	/*
	 * Two incoming fragments arriving backwards.
	 * Both fragments will also be refragmented twice (ie. 6 outgoing fragments).
	 */
	frag = create_fragment_ipv4(2500, create_skb_ipv4_tcp_fragment, 0, 0, 3020);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	frag = create_fragment_ipv4(3000, create_skb_ipv4_tcp, 0, IP_MF, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	/* Call the function */
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_multiple_4to6_tcp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_multiple_4to6_icmp_info(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;
	int payload_len;
	u16 offset;

	if (!validate_fragment_count(pkt, 2))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	offset = 0;
	payload_len = 1280 - sizeof(struct ipv6hdr) - sizeof(struct frag_hdr) - sizeof(struct icmp6hdr);

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_icmp6(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), 1280 - sizeof(struct ipv6hdr), NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, IP6_MF, NEXTHDR_ICMP))
		return false;
	if (!validate_icmp6_hdr(frag_get_icmp6_hdr(frag), 2000, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = 1232;
	payload_len = 776;

	if (!validate_frag_ipv6(frag, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the second skb...");
	if (!validate_ipv6_hdr(frag_get_ipv6_hdr(frag), sizeof(struct frag_hdr) + payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(frag_get_fragment_hdr(frag), offset, 0, NEXTHDR_ICMP))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset - sizeof(struct udphdr)))
		return false;

	return true;
}

static bool test_multiple_4to6_icmp_info(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	/* Init */
	INIT_LIST_HEAD(&pkt_in.fragments);
	INIT_LIST_HEAD(&pkt_out.fragments);
	if (!create_tuple_ipv6(&tuple, L4PROTO_ICMP))
		return false;

	/**
	 * A no-fragment,
	 * going to be fragmented.
	 */
	frag = create_fragment_ipv4(2000, create_skb_ipv4_icmp_info, 0, 0, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	/* Call the function */
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_multiple_4to6_icmp_info(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_multiple_6to4_udp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;
	int payload_len;
	u16 offset;

	if (!validate_fragment_count(pkt, 2))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	offset = 0;
	payload_len = 100;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_udp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len,
			4321, 0, IP_MF, offset, IPPROTO_UDP, tuple))
		return false;
	if (!validate_udp_hdr(frag_get_udp_hdr(frag), payload_len, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = sizeof(struct udphdr) + 100;
	payload_len = 100;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the second skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag), sizeof(struct iphdr) + payload_len,
			4321, 0, 0, offset, IPPROTO_UDP, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool test_multiple_6to4_udp(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	/* Init */
	INIT_LIST_HEAD(&pkt_in.fragments);
	INIT_LIST_HEAD(&pkt_out.fragments);
	if (!create_tuple_ipv4(&tuple, L4PROTO_UDP))
		return false;

	frag = create_fragment_ipv6(100, create_skb_ipv6_udp_fragment_1, IP6_MF, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	frag = create_fragment_ipv6(100, create_skb_ipv6_udp_fragment_n, 0, 108);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	/* Call the function */
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_multiple_6to4_udp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_multiple_6to4_tcp(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;
	int payload_len;
	u16 offset;

	if (!validate_fragment_count(pkt, 2))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	offset = 0;
	payload_len = 100;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_tcp(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len,
			4321, 0, IP_MF, offset, IPPROTO_TCP, tuple))
		return false;
	if (!validate_tcp_hdr(frag_get_tcp_hdr(frag), tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = sizeof(struct tcphdr) + 100;
	payload_len = 100;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the second skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag), sizeof(struct iphdr) + payload_len,
			4321, 0, 0, offset, IPPROTO_TCP, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool test_multiple_6to4_tcp(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	/* Init */
	INIT_LIST_HEAD(&pkt_in.fragments);
	INIT_LIST_HEAD(&pkt_out.fragments);
	if (!create_tuple_ipv4(&tuple, L4PROTO_TCP))
		return false;

	frag = create_fragment_ipv6(100, create_skb_ipv6_tcp_fragment_1, IP6_MF, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	frag = create_fragment_ipv6(100, create_skb_ipv6_tcp_fragment_n, 0, 120);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	/* Call the function */
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_multiple_6to4_tcp(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

static bool validate_pkt_multiple_6to4_icmp_info(struct packet *pkt, struct tuple *tuple)
{
	struct fragment *frag;
	int payload_len;
	u16 offset;

	if (!validate_fragment_count(pkt, 2))
		return false;

	log_debug("Validating the first fragment...");
	frag = container_of(pkt->fragments.next, struct fragment, next);
	offset = 0;
	payload_len = 100;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_icmp4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag),
			sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_len,
			4321, 0, IP_MF, offset, IPPROTO_ICMP, tuple))
		return false;
	if (!validate_icmp4_hdr(frag_get_icmp4_hdr(frag), 1, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, offset))
		return false;

	log_debug("Validating the second fragment...");
	frag = container_of(frag->next.next, struct fragment, next);
	offset = sizeof(struct icmphdr) + 100;
	payload_len = 100;

	if (!validate_frag_ipv4(frag))
		return false;
	if (!validate_frag_empty_l4(frag))
		return false;
	if (!validate_frag_payload(frag, payload_len))
		return false;

	log_debug("Validating the second skb...");
	if (!validate_ipv4_hdr(frag_get_ipv4_hdr(frag), sizeof(struct iphdr) + payload_len,
			4321, 0, 0, offset, IPPROTO_ICMP, tuple))
		return false;
	if (!validate_payload(frag_get_payload(frag), payload_len, 0))
		return false;

	return true;
}

static bool test_multiple_6to4_icmp_info(void)
{
	struct packet pkt_in, pkt_out;
	struct tuple tuple;
	enum verdict result;
	struct fragment *frag;

	/* Init */
	INIT_LIST_HEAD(&pkt_in.fragments);
	INIT_LIST_HEAD(&pkt_out.fragments);
	if (!create_tuple_ipv4(&tuple, L4PROTO_ICMP))
		return false;

	frag = create_fragment_ipv6(100, create_skb_ipv6_icmp_info_fragment_1, IP6_MF, 0);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	frag = create_fragment_ipv6(100, create_skb_ipv6_icmp_info_fragment_n, 0, 108);
	if (!frag)
		goto fail;
	list_add(&frag->next, pkt_in.fragments.prev);

	/* Call the function */
	result = translating_the_packet(&tuple, &pkt_in, &pkt_out);
	if (result != VER_CONTINUE)
		goto fail;

	/* Validate */
	if (!validate_pkt_multiple_6to4_icmp_info(&pkt_out, &tuple))
		goto fail;

	/* Yaaaaaaaaay */
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return true;

fail:
	pkt_kfree(&pkt_in, false);
	pkt_kfree(&pkt_out, false);
	return false;
}

int init_module(void)
{
	START_TESTS("Translating the Packet");

	if (str_to_addr6("1::1", &dummies6[0]) != 0)
		return -EINVAL;
	if (str_to_addr6("2::2", &dummies6[1]) != 0)
		return -EINVAL;
	if (str_to_addr4("1.1.1.1", &dummies4[0]) != 0)
		return -EINVAL;
	if (str_to_addr4("2.2.2.2", &dummies4[1]) != 0)
		return -EINVAL;

	translate_packet_init();

	/* Checksum tests */
	CALL_TEST(test_post_tcp_csum_6to4(), "Recomputed TCP checksum 6->4");
	CALL_TEST(test_post_udp_csum_6to4(), "Recomputed UDP checksum 6->4");
	CALL_TEST(test_update_csum_4to6(), "Recomputed checksum 4->6");

	/* Misc single function tests */
	CALL_TEST(test_function_has_unexpired_src_route(), "Unexpired source route querier");
	CALL_TEST(test_function_build_id_field(), "Identification builder");
	CALL_TEST(test_function_icmp6_minimum_mtu(), "ICMP6 Minimum MTU function");
	CALL_TEST(test_function_icmp4_to_icmp6_param_prob(), "Param problem function");

	CALL_TEST(test_function_build_tos_field(), "Build TOS function");
	CALL_TEST(test_function_generate_ipv4_id_nofrag(), "Generate id function (no frag)");
	CALL_TEST(test_function_generate_df_flag(), "Generate DF flag function");
	CALL_TEST(test_function_build_protocol_field(), "Build protocol function");
	CALL_TEST(test_function_has_nonzero_segments_left(), "Segments left indicator function");
	CALL_TEST(test_function_generate_ipv4_id_dofrag(), "Generate id function (frag)");
	CALL_TEST(test_function_icmp4_minimum_mtu(), "ICMP4 Minimum MTU function");

	/* Full packet translation tests */
	CALL_TEST(test_simple_4to6_udp(), "Simple 4->6 UDP");
	CALL_TEST(test_simple_4to6_tcp(), "Simple 4->6 TCP");
	CALL_TEST(test_simple_4to6_icmp_info(), "Simple 4->6 ICMP info");
	CALL_TEST(test_simple_4to6_icmp_error(), "Simple 4->6 ICMP error");

	CALL_TEST(test_simple_6to4_udp(), "Simple 6->4 UDP");
	CALL_TEST(test_simple_6to4_tcp(), "Simple 6->4 TCP");
	CALL_TEST(test_simple_6to4_icmp_info(), "Simple 6->4 ICMP info");
	CALL_TEST(test_simple_6to4_icmp_error(), "Simple 6->4 ICMP error");

	CALL_TEST(test_multiple_4to6_udp(), "Multiple 4->6 UDP");
	CALL_TEST(test_multiple_4to6_tcp(), "Multiple 4->6 TCP");
	CALL_TEST(test_multiple_4to6_icmp_info(), "Multiple 4->6 ICMP info");

	CALL_TEST(test_multiple_6to4_udp(), "Multiple 6->4 UDP");
	CALL_TEST(test_multiple_6to4_tcp(), "Multiple 6->4 TCP");
	CALL_TEST(test_multiple_6to4_icmp_info(), "Multiple 6->4 ICMP info");

	translate_packet_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
