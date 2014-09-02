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

static struct sk_buff *create_skb4(u16 payload_len,
		int (*skb_create_fn)(struct ipv4_pair *, struct sk_buff **, u16))
{
	struct sk_buff *skb;
	struct ipv4_pair pair4;

	pair4.remote.address = dummies4[0];
	pair4.remote.l4_id = 5644;
	pair4.local.address = dummies4[1];
	pair4.local.l4_id = 6721;

	return (is_error(skb_create_fn(&pair4, &skb, payload_len))) ? NULL : skb;
}

static struct sk_buff *create_skb6(u16 payload_len,
		int (*skb_create_fn)(struct ipv6_pair *, struct sk_buff **, u16))
{
	struct sk_buff *skb;
	struct ipv6_pair pair6;

	pair6.remote.address = dummies6[0];
	pair6.remote.l4_id = 5644;
	pair6.local.address = dummies6[1];
	pair6.local.l4_id = 6721;

	return (is_error(skb_create_fn(&pair6, &skb, payload_len))) ? NULL : skb;
}

static struct sk_buff *create_frag_skb4(u16 payload_len, u16 total_l4_len, bool df,	bool mf,
		u16 frag_offset, int (*skb_create_frag_fn) (struct ipv4_pair *, struct sk_buff **, u16,
				u16 , bool, bool, u16))
{
	struct sk_buff *skb;
	struct ipv4_pair pair4;

	pair4.remote.address = dummies4[0];
	pair4.remote.l4_id = 5644;
	pair4.local.address = dummies4[1];
	pair4.local.l4_id = 6721;

	if (is_error(skb_create_frag_fn(&pair4, &skb, payload_len, total_l4_len, df, mf, frag_offset)))
		skb = NULL;

	return skb;
}

static struct sk_buff *create_frag_skb6(u16 payload_len, u16 total_l4_len, bool mf,	u16 frag_offset,
		int (*skb_create_frag_fn) (struct ipv6_pair *, struct sk_buff **, u16, u16 , bool, u16))
{
	struct sk_buff *skb;
	struct ipv6_pair pair6;

	pair6.remote.address = dummies6[0];
	pair6.remote.l4_id = 5644;
	pair6.local.address = dummies6[1];
	pair6.local.l4_id = 6721;

	if (is_error(skb_create_frag_fn(&pair6, &skb, payload_len, total_l4_len, mf, frag_offset)))
		skb = NULL;

	return skb;
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
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple;
	__sum16 expected_csum;
	bool success = true;

	if (init_pair6(&pair6, "1::4", 1234, "6::9", 2345) != 0)
		return false;
	if (init_pair4(&pair4, "1.2.3.4", 1234, "6.7.8.9", 2345) != 0)
		return false;

	/* We're assuming both of these will have the same layer-4 headers and payloads. */
	if (is_error(create_skb_ipv6_tcp(&pair6, &skb_in, 100)))
		goto error;
	if (is_error(create_skb_ipv4_tcp(&pair4, &skb_out, 100)))
		goto error;

	expected_csum = tcp_hdr(skb_out)->check;
	tuple.src.l4_id = 1234;
	tuple.dst.l4_id = 2345;

	/*
	 * We're also assuming that post_tcp_ipv4() will override skb_out's checksum
	 * (and that's what we're going to test).
	 */
	success &= assert_equals_int(0, post_tcp_ipv4(&tuple, skb_in, skb_out), "result");
	success &= assert_equals_csum(expected_csum, tcp_hdr(skb_out)->check, "Checksum");

	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return success;

error:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return false;
}

static bool test_post_udp_csum_6to4(void)
{
	struct sk_buff *skb_in = NULL, *skb_out = NULL;
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;
	struct tuple tuple;
	__sum16 expected_csum;
	bool success = true;

	if (init_pair6(&pair6, "1::4", 1234, "6::9", 2345) != 0)
		return false;
	if (init_pair4(&pair4, "1.2.3.4", 1234, "6.7.8.9", 2345) != 0)
		return false;

	/* We're assuming both of these will have the same layer-4 headers and payloads. */
	if (is_error(create_skb_ipv6_udp(&pair6, &skb_in, 100)))
		goto error;
	if (is_error(create_skb_ipv4_udp(&pair4, &skb_out, 100)))
		goto error;

	expected_csum = udp_hdr(skb_out)->check;
	tuple.src.l4_id = 1234;
	tuple.dst.l4_id = 2345;

	/*
	 * We're also assuming that post_tcp_ipv4() will override skb_out's checksum
	 * (and that's what we're going to test).
	 */
	success &= assert_equals_int(0, post_udp_ipv4(&tuple, skb_in, skb_out), "result");
	success &= assert_equals_csum(expected_csum, udp_hdr(skb_out)->check, "Checksum");

	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return success;

error:
	kfree_skb(skb_in);
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
	if (init_ipv4_hdr(hdr4, datagram_len, IPPROTO_TCP, &pair4, true, false, 0) != 0)
		return false;
	if (init_tcp_hdr(hdr_tcp4, ETH_P_IP, datagram_len, &pair4) != 0)
		return false;
	if (init_payload_normal(hdr_tcp4 + 1, 100) != 0)
		return false;
	if (ipv4_tcp_post(hdr_tcp4, datagram_len, &pair4) != 0)
		return false;

	hdr6 = (struct ipv6hdr *) &out_pkt[0];
	hdr_tcp6 = (struct tcphdr *) (hdr6 + 1);
	if (init_ipv6_hdr(hdr6, datagram_len, NEXTHDR_TCP, &pair6, true, false, 0) != 0)
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
		log_err("Can't allocate a test header.");
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

	bool old_lower_mtu_fail = config->lower_mtu_fail;
	__u16 *old_plateaus = config->mtu_plateaus;
	__u16 old_plateaus_count = config->mtu_plateau_count;

	config->lower_mtu_fail = false;
	config->mtu_plateaus = plateaus;
	config->mtu_plateau_count = ARRAY_SIZE(plateaus);

	/* Test the bare minimum functionality. */
	success &= assert_equals_u32(21, min_mtu(1, 100, 100, 0), "No hacks, min is packet");
	success &= assert_equals_u32(1, min_mtu(100, 1, 100, 0), "No hacks, min is in");
	success &= assert_equals_u32(21, min_mtu(100, 100, 1, 0), "No hacks, min is out");

	if (!success)
		goto revert;

	/* Test hack 1: MTU is overriden if some router set is as zero. */
	for (i = 1500; i > 1400 && success; --i)
		success &= assert_equals_u32(1420, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 1400; i > 1200 && success; --i)
		success &= assert_equals_u32(1220, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 1200; i > 600 && success; --i)
		success &= assert_equals_u32(620, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 600; i > 0 && success; --i)
		success &= assert_equals_u32(20, min_mtu(0, 1600, 1600, i), "Override packet MTU");

	success &= assert_equals_u32(1, min_mtu(0, 1, 100, 1000), "Override packet MTU, min is in");
	success &= assert_equals_u32(21, min_mtu(0, 100, 1, 1000), "Override packet MTU, min is out");

	if (!success)
		goto revert;

	/* Test hack 2: User wants us to try to improve the failure rate. */
	config->lower_mtu_fail = true;

	success &= assert_equals_u32(1300, min_mtu(1, 2, 2, 0), "Improve rate, min is packet");
	success &= assert_equals_u32(1300, min_mtu(2, 1, 2, 0), "Improve rate, min is in");
	success &= assert_equals_u32(1300, min_mtu(2, 2, 1, 0), "Improve rate, min is out");

	success &= assert_equals_u32(1420, min_mtu(1400, 1500, 1500, 0), "Fail improve rate, packet");
	success &= assert_equals_u32(1400, min_mtu(1500, 1400, 1500, 0), "Fail improve rate, in");
	success &= assert_equals_u32(1420, min_mtu(1500, 1500, 1400, 0), "Fail improve rate, out");

	if (!success)
		goto revert;

	/* Test both hacks at the same time. */
	success &= assert_equals_u32(1300, min_mtu(0, 700, 700, 1000), "2 hacks, override packet");
	success &= assert_equals_u32(1300, min_mtu(0, 1, 100, 1000), "2 hacks, override in");
	success &= assert_equals_u32(1300, min_mtu(0, 100, 1, 1000), "2 hacks, override out");

	success &= assert_equals_u32(1420, min_mtu(0, 1500, 1500, 1500), "2 hacks, packet/not 1280");
	success &= assert_equals_u32(1400, min_mtu(0, 1400, 1500, 1500), "2 hacks, in/not 1280");
	success &= assert_equals_u32(1420, min_mtu(0, 1500, 1400, 1500), "2 hacks, out/not 1280");

	/* Fall through. */
revert:
	config->lower_mtu_fail = old_lower_mtu_fail;
	config->mtu_plateaus = old_plateaus;
	config->mtu_plateau_count = old_plateaus_count;
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
	success &= assert_equals_int(0, icmp4_to_icmp6_param_prob(&hdr4, &hdr6), "func result 1");
	success &= assert_equals_u8(ICMPV6_HDR_FIELD, hdr6.icmp6_code, "code");
	success &= assert_equals_u8(7, be32_to_cpu(hdr6.icmp6_pointer), "pointer");

	hdr4.icmp4_unused = cpu_to_be32(0x05000000);
	success &= assert_equals_int(-EINVAL, icmp4_to_icmp6_param_prob(&hdr4, &hdr6), "func result 2");

	return success;
}

static bool test_function_get_traffic_class(void)
{
	__u8 ipv6_header[4]; /* We don't really need the rest of the bytes. */
	bool success = true;

	/*
	 * version: 6
	 * traffic class: 78
	 * flow label: 9abcd
	 */
	ipv6_header[0] = 0x67;
	ipv6_header[1] = 0x89;
	ipv6_header[2] = 0xab;
	ipv6_header[3] = 0xcd;
	success &= assert_equals_u8(0x78, get_traffic_class((struct ipv6hdr *) ipv6_header), "Simple");

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
		log_err("Could not allocate a test packet.");
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
		log_err("Could not allocate a test packet.");
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

static bool test_4to6_udp(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv6(&tuple, L4PROTO_UDP))
		goto end;

	skb_in = create_skb4(100, create_skb_ipv4_udp);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV6, sizeof(struct ipv6hdr))
			&& validate_cb_l4(skb_out, L4PROTO_UDP, sizeof(struct udphdr))
			&& validate_cb_payload(skb_out, 100)
			&& validate_ipv6_hdr(ipv6_hdr(skb_out),
					skb_l4hdr_len(skb_out) + skb_payload_len(skb_out),
					NEXTHDR_UDP, &tuple)
			&& validate_udp_hdr(udp_hdr(skb_out), 100, &tuple)
			&& validate_payload(skb_payload(skb_out), 100, 0);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static bool test_4to6_tcp(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv6(&tuple, L4PROTO_TCP))
		goto end;
	skb_in = create_skb4(100, create_skb_ipv4_tcp);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV6, sizeof(struct ipv6hdr))
			&& validate_cb_l4(skb_out, L4PROTO_TCP, sizeof(struct tcphdr))
			&& validate_cb_payload(skb_out, 100)
			&& validate_ipv6_hdr(ipv6_hdr(skb_out),
					skb_l4hdr_len(skb_out) + skb_payload_len(skb_out),
					NEXTHDR_TCP, &tuple)
			&& validate_tcp_hdr(tcp_hdr(skb_out), &tuple)
			&& validate_payload(skb_payload(skb_out), 100, 0);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static bool test_4to6_icmp_info(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv6(&tuple, L4PROTO_ICMP))
		goto end;
	skb_in = create_skb4(100, create_skb_ipv4_icmp_info);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV6, sizeof(struct ipv6hdr))
			&& validate_cb_l4(skb_out, L4PROTO_ICMP, sizeof(struct icmp6hdr))
			&& validate_cb_payload(skb_out, 100)
			&& validate_ipv6_hdr(ipv6_hdr(skb_out),
					skb_l4hdr_len(skb_out) + skb_payload_len(skb_out),
					NEXTHDR_ICMP, &tuple)
			&& validate_icmp6_hdr(icmp6_hdr(skb_out), 5644, &tuple)
			&& validate_payload(skb_payload(skb_out), 100, 0);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static bool test_4to6_icmp_error(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv6(&tuple, L4PROTO_ICMP))
		goto end;
	skb_in = create_skb4(100, create_skb_ipv4_icmp_error);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV6, sizeof(struct ipv6hdr))
			&& validate_cb_l4(skb_out, L4PROTO_ICMP, sizeof(struct icmp6hdr))
			/* The payload was a packet, which was also translated, so it grew. */
			&& validate_cb_payload(skb_out, 120)
			&& validate_ipv6_hdr(ipv6_hdr(skb_out),
					skb_l4hdr_len(skb_out) + skb_payload_len(skb_out),
					NEXTHDR_ICMP, &tuple)
			&& validate_icmp6_hdr_error(icmp6_hdr(skb_out))
			&& validate_inner_pkt_ipv6(skb_payload(skb_out), 120);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static bool test_6to4_udp(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv4(&tuple, L4PROTO_UDP))
		goto end;
	skb_in = create_skb6(100, create_skb_ipv6_udp);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV4, sizeof(struct iphdr))
			&& validate_cb_l4(skb_out, L4PROTO_UDP, sizeof(struct udphdr))
			&& validate_cb_payload(skb_out, 100)
			&& validate_ipv4_hdr(ip_hdr(skb_out),
					sizeof(struct iphdr) + sizeof(struct udphdr) + 100,
					0, IP_DF, 0, 0, IPPROTO_UDP, &tuple)
			&& validate_udp_hdr(udp_hdr(skb_out), 100, &tuple)
			&& validate_payload(skb_payload(skb_out), 100, 0);
	/* Fall through. */

end:
	if (skb_in)
		kfree_skb(skb_in);
	if (skb_out)
		kfree_skb(skb_out);
	return result;
}

static bool test_6to4_tcp(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv4(&tuple, L4PROTO_TCP))
		goto end;
	skb_in = create_skb6(100, create_skb_ipv6_tcp);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV4, sizeof(struct iphdr))
			&& validate_cb_l4(skb_out, L4PROTO_TCP, sizeof(struct tcphdr))
			&& validate_cb_payload(skb_out, 100)
			&& validate_ipv4_hdr(ip_hdr(skb_out),
					sizeof(struct iphdr) + sizeof(struct tcphdr) + 100,
					0, IP_DF, 0, 0, IPPROTO_TCP, &tuple)
			&& validate_tcp_hdr(tcp_hdr(skb_out), &tuple)
			&& validate_payload(skb_payload(skb_out), 100, 0);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static bool test_6to4_icmp_info(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv4(&tuple, L4PROTO_ICMP))
		goto end;
	skb_in = create_skb6(100, create_skb_ipv6_icmp_info);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV4, sizeof(struct iphdr))
			&& validate_cb_l4(skb_out, L4PROTO_ICMP, sizeof(struct icmphdr))
			&& validate_cb_payload(skb_out, 100)
			&& validate_ipv4_hdr(ip_hdr(skb_out),
					sizeof(struct iphdr) + sizeof(struct icmphdr) + 100,
					0, IP_DF, 0, 0, IPPROTO_ICMP, &tuple)
			&& validate_icmp4_hdr(icmp_hdr(skb_out), 5644, &tuple)
			&& validate_payload(skb_payload(skb_out), 100, 0);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static bool test_6to4_icmp_error(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv4(&tuple, L4PROTO_ICMP))
		goto end;
	skb_in = create_skb6(100, create_skb_ipv6_icmp_error);
	if (!skb_in)
		goto end;

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragment_count(skb_out, 1)
			&& validate_cb_l3(skb_out, L3PROTO_IPV4, sizeof(struct iphdr))
			&& validate_cb_l4(skb_out, L4PROTO_ICMP, sizeof(struct icmphdr))
			/* The payload was a packet, which was also translated, so it shrank. */
			&& validate_cb_payload(skb_out, 80)
			&& validate_ipv4_hdr(ip_hdr(skb_out),
					sizeof(struct iphdr) + sizeof(struct icmphdr) + 80,
					0, IP_DF, 0, 0, IPPROTO_ICMP, &tuple)
			&& validate_icmp4_hdr_error(icmp_hdr(skb_out))
			&& validate_inner_pkt_ipv4(skb_payload(skb_out), 80);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static bool validate_fragment(struct sk_buff *skb, bool is_first, bool is_last,
		u16 offset, u16 payload_len, u16 payload_offset, struct tuple *tuple)
{
	u16 mf = is_last ? 0 : IP6_MF;
	u16 hdr_payload_len = sizeof(struct frag_hdr) + (is_first ? sizeof(struct udphdr) : 0)
			+ payload_len;

	if (!skb) {
		log_err("The skb is NULL.");
		return false;
	}

	if (!validate_cb_l3(skb, L3PROTO_IPV6, sizeof(struct ipv6hdr) + sizeof(struct frag_hdr)))
		return false;
	if (!validate_cb_l4(skb, L4PROTO_UDP, is_first ? sizeof(struct udphdr) : 0))
		return false;
	if (!validate_cb_payload(skb, payload_len))
		return false;

	if (!validate_ipv6_hdr(ipv6_hdr(skb), hdr_payload_len, NEXTHDR_FRAGMENT, tuple))
		return false;
	if (!validate_frag_hdr(get_extension_header(ipv6_hdr(skb), NEXTHDR_FRAGMENT), offset, mf,
			NEXTHDR_UDP))
		return false;
	if (is_first && !validate_udp_hdr(udp_hdr(skb), 3000, tuple))
		return false;
	if (!validate_payload(skb_payload(skb), payload_len, payload_offset))
		return false;

	return true;
}

static bool validate_fragments(struct sk_buff *skb, struct tuple *tuple)
{
	if (!validate_fragment_count(skb, 3))
		return false;

	log_debug("Validating the first skb...");
	if (!validate_fragment(skb, true, false, 0, 1224, 0, tuple))
		return false;

	log_debug("Validating the second skb...");
	skb = skb->next;
	if (!validate_fragment(skb, false, false, 1232, 1232, 1224, tuple))
		return false;

	log_debug("Validating the third skb...");
	skb = skb->next;
	if (!validate_fragment(skb, false, true, 2464, 544, 2456, tuple))
		return false;

	return true;
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

static bool test_multiple_4to6_fragment(void)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	bool result = false;

	if (!create_tuple_ipv6(&tuple, L4PROTO_UDP))
		goto end;
	skb_in = create_skb4(3000, create_skb_ipv4_udp);
	if (!skb_in)
		goto end;
	ip_hdr(skb_in)->frag_off = build_ipv4_frag_off_field(false, false, 0);

	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	result = validate_fragments(skb_out, &tuple);
	/* Fall through. */

end:
	kfree_skb(skb_in);
	kfree_skb(skb_out);
	return result;
}

static void append_frag_to_skb(struct sk_buff *prev_skb, struct sk_buff *skb)
{
	prev_skb->next = skb;
	skb->prev = prev_skb;
	skb->next = NULL;
}

static struct sk_buff *create_frags_4(int total_frags, bool mf[], u16 frag_offset[], bool df,
		u16 total_len, u16 payload_len[], int (*skb_create_frag_fn) (struct ipv4_pair *,
				struct sk_buff **, u16, u16, bool, bool, u16))
{
	struct sk_buff *root_skb, *prev_skb, *tmp_skb;
	int i;
	root_skb = prev_skb = tmp_skb = NULL;

	root_skb = create_frag_skb4(payload_len[0], total_len, df, mf[0], frag_offset[0],
			skb_create_frag_fn); /* First Frag.*/
	if (!root_skb)
		goto end;
	tmp_skb = root_skb;

	for (i = 1; i < total_frags; i++) {
		prev_skb = tmp_skb;
		tmp_skb = create_frag_skb4(payload_len[i], total_len, df, mf[i], frag_offset[i],
				skb_create_frag_fn);
		if (!tmp_skb)
			goto end;
		append_frag_to_skb(prev_skb, tmp_skb);
	}

	return root_skb;
end:
	kfree_skb_queued(root_skb);
	return NULL;
}

static bool test_multiple_4to6(l4_protocol l4proto, bool df)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	u16 frag_offset[] = {0, 16, 32, 48};
	u16 payload_len[] = {16, 16, 16, 8};
	/* IPv4 Parameters. */
	bool mf_flags[] = {true, true, true, false};
	u16 total_payload = 56;
	u16 total_frags = 4;
	u16 total_l4_len;
	/* IPv6 Parameters. (To evaluate). */
	bool is_first[] = {true, false, false, false};
	bool is_last[] = {false, false, false, true};
	u16 payload_offset[] = {0, 0, 0, 0};

	if (!create_tuple_ipv6(&tuple, l4proto))
		goto end;

	/* Create Steps SKBs*/
	switch (l4proto) {
	case (L4PROTO_TCP):
		total_l4_len = total_payload + sizeof(struct tcphdr);
		skb_in = create_frags_4(total_frags, mf_flags, frag_offset, df, total_l4_len, payload_len,
				create_skb_ipv4_tcp_frag);
		if (!skb_in)
			goto end;
		break;
	case (L4PROTO_UDP):
		total_l4_len = total_payload + sizeof(struct udphdr);
		skb_in = create_frags_4(total_frags, mf_flags, frag_offset, df, total_l4_len, payload_len,
				create_skb_ipv4_udp_frag);
		if (!skb_in)
			goto end;
		break;
	case (L4PROTO_ICMP):
		total_l4_len = total_payload + sizeof(struct icmphdr);
		skb_in = create_frags_4(total_frags, mf_flags, frag_offset, df, total_l4_len, payload_len,
				create_skb_ipv4_icmp_info_frag);
		if (!skb_in)
			goto end;
		break;
	default:
		log_debug("Invalid l4 protocol: %u", l4proto);
		return false;
	}

	/* Translate step SKBs*/
	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	/* Evaluating SKBs*/
	if (!validate_frags6(skb_out, &tuple, total_frags, is_first, is_last, frag_offset, payload_len,
			payload_offset, total_payload, l4proto))
		goto end;

	kfree_skb_queued(skb_in);
	kfree_skb_queued(skb_out);
	return true;
end:
	kfree_skb_queued(skb_in);
	kfree_skb_queued(skb_out);
	return false;
}

static bool validate_frag4(struct tuple *tuple, struct sk_buff *skb, l4_protocol l4proto,
		u16 payload_len, u16 payload_offset, bool is_first, bool is_last, u16 frag_off,
		u16 total_payload)
{
	size_t l4hdr_size;
	u8 ip_proto;
	u16 mf = is_last ? 0 : IP_MF;
	u16 total_l3_len;

	switch (l4proto) {
	case (L4PROTO_TCP):
		l4hdr_size = sizeof(struct tcphdr);
		ip_proto = IPPROTO_TCP;
		break;
	case (L4PROTO_UDP):
		l4hdr_size = sizeof(struct udphdr);
		ip_proto = IPPROTO_UDP;
		break;
	case (L4PROTO_ICMP):
		l4hdr_size = sizeof(struct icmphdr);
		ip_proto = IPPROTO_ICMP;
		break;
	default:
		log_debug("Invalid l4 protocol: %u", l4proto);
		return false;
	}
	total_l3_len = sizeof(struct iphdr) + payload_len + (is_first ? l4hdr_size : 0);

	if (!validate_cb_l3(skb, L3PROTO_IPV4, sizeof(struct iphdr)))
		return false;
	if (!validate_cb_l4(skb, l4proto, is_first ? l4hdr_size : 0))
		return false;
	if (!validate_cb_payload(skb, payload_len))
		return false;
	if (!validate_ipv4_hdr(ip_hdr(skb),	total_l3_len, 4321, 0, mf, frag_off, ip_proto, tuple))
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
		if (is_first && !validate_icmp4_hdr(icmp_hdr(skb), 1234, tuple))
			return false;
		break;
	}
	if (!validate_payload(skb_payload(skb), payload_len, payload_offset))
		return false;

	return true;
}

static bool validate_frags4(struct tuple *tuple, struct sk_buff *skb, int total_frags,
		l4_protocol l4proto, u16 payload_len[], u16 payload_offset[], bool is_first[],
		bool is_last[], u16 frag_off[], u16 total_payload)
{
	int i;

	if (!skb)
		return false;

	if (!validate_fragment_count(skb, total_frags))
		return false;

	for (i = 0; i < total_frags; i++) {
		log_debug("Validating fragment #%d", i);
		if (!validate_frag4(tuple, skb, l4proto, payload_len[i], payload_offset[i], is_first[i],
				is_last[i],frag_off[i], total_payload))
			return false;
		skb = skb->next;
	}

	return true;
}

static struct sk_buff *create_frags_6(int total_frags, u16 payload_len[], u16 total_l4_len,
		bool mf[], u16 frag_offset[], int (*skb_create_frag_fn) (struct ipv6_pair *,
				struct sk_buff **, u16,	u16, bool, u16))
{
	struct sk_buff *root_skb, *prev_skb, *tmp_skb;
	int i;
	root_skb = prev_skb = tmp_skb = NULL;

	root_skb = create_frag_skb6(payload_len[0], total_l4_len, mf[0], frag_offset[0],
			skb_create_frag_fn); /* First Frag.*/
	if (!root_skb)
		goto end;
	tmp_skb = root_skb;

	for (i = 1; i < total_frags; i++) {
		prev_skb = tmp_skb;
		tmp_skb = create_frag_skb6(payload_len[i], total_l4_len, mf[i], frag_offset[i],
				skb_create_frag_fn);
		if (!tmp_skb)
			goto end;
		append_frag_to_skb(prev_skb, tmp_skb);
	}

	return root_skb;
end:
	kfree_skb_queued(root_skb);
	return NULL;

}

static bool test_multiple_6to4(l4_protocol l4proto)
{
	struct sk_buff *skb_in, *skb_out;
	struct tuple tuple;
	/* IPv6 Parameters. */
	u16 payload_len[] = {200, 200, 200, 80};
	u16 frag_offset[] = {0, 200, 400, 600};
	u16 total_payload = 680;
	u16 total_l4_len;
	bool mf[] = {true, true, true, false};
	int total_frags = 4;
	/* IPv4 evaluate. */
	u16 payload_offset[] = {0, 0, 0, 0};
	bool is_first[] = {true, false, false, false};
	bool is_last[] = {false, false, false, true};
	skb_in = skb_out = NULL;

	if (!create_tuple_ipv4(&tuple, l4proto))
		goto end;

	/*Create IPv6 Fragments. */
	switch (l4proto) {
	case (L4PROTO_TCP):
		total_l4_len = total_payload + sizeof(struct tcphdr);
		skb_in = create_frags_6(total_frags, payload_len, total_l4_len, mf,	frag_offset,
				create_skb_ipv6_tcp_frag);
		if (!skb_in)
				goto end;
		break;
	case (L4PROTO_UDP):
		total_l4_len = total_payload + sizeof(struct udphdr);
		skb_in = create_frags_6(total_frags, payload_len, total_l4_len, mf,	frag_offset,
				create_skb_ipv6_udp_frag);
		if (!skb_in)
				goto end;
		break;
	case (L4PROTO_ICMP):
		total_l4_len = total_payload + sizeof(struct icmphdr);
		skb_in = create_frags_6(total_frags, payload_len, total_l4_len, mf,	frag_offset,
				create_skb_ipv6_icmp_info_frag);
		if (!skb_in)
				goto end;
		break;
	default:
		log_debug("Invalid l4 protocol: %u", l4proto);
		return false;
	}


	/* Translate IPv6 into IPv4 Fragments */
	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	/* Evaluating the IPv4 Fragments*/
	if (!validate_frags4(&tuple, skb_out, total_frags, l4proto, payload_len, payload_offset,
			is_first, is_last, frag_offset, total_payload))
		goto end;
	/* Fall through. */

	kfree_skb_queued(skb_in);
	kfree_skb_queued(skb_out);
	return true;
end:
	kfree_skb_queued(skb_in);
	kfree_skb_queued(skb_out);
	return false;
}

static bool test_big_multiple_4to6(l4_protocol l4proto, bool df)
{
	struct sk_buff *skb_in = NULL;
	struct sk_buff *skb_out = NULL;
	struct tuple tuple;
	u16 frag_offset[] = {0, 3008, 6008};
	u16 payload_len[] = {3000, 3000, 3000};
	/* IPv4 Parameters. */
	bool mf_flags[] = {true, true, false};
	u16 total_payload = 9000;
	int total_frags = 3;
	u16 total_l4_len;
	/* IPv6 Parameters. (To evaluate). */
	bool is_first[] = {true, false, false, false, false, false, false, false, false};
	bool is_last[] = {false, false, false, false, false, false, false, false, true};
	u16 frag6_offset[] = {0, 1232, 2464, 3008, 4240, 5472, 6008, 7240, 8472};
	u16 payload6_len[] = {1224, 1232, 544, 1232, 1232, 536, 1232, 1232, 536};
	u16 payload_offset[] = {0, 1224, 2456, 0, 1232, 2464, 0, 1232, 2464};
	int total_frags6 = 9;
	/*TODO: Fix it, in order to accept TCP, this is because the offset is fixed by 8 bytes and
	 * sizeof(struct tcphdr) = 20 bytes*/
	if (!create_tuple_ipv6(&tuple, l4proto))
		goto end;

	/* Create Steps SKBs*/
	switch (l4proto) {
	case (L4PROTO_TCP):
		total_l4_len = total_payload + sizeof(struct tcphdr);
//		frag_offset[] = {0, 3020, 6020};
//		frag6_offset[] = {0, 1220, 2452, 3008, 4240, 5472, 6008, 7240, 8472};
//		payload6_len[] = {1212, 1232, 556, 1232, 1232, 536, 1232, 1232, 536};
//		payload_offset[] = {0, 1212, 2456, 0, 1232, 2464, 0, 1232, 2464};
		skb_in = create_frags_4(total_frags, mf_flags, frag_offset, df, total_l4_len, payload_len,
				create_skb_ipv4_tcp_frag);
		if (!skb_in)
			goto end;
		break;
	case (L4PROTO_UDP):
		total_l4_len = total_payload + sizeof(struct udphdr);
		skb_in = create_frags_4(total_frags, mf_flags, frag_offset, df, total_l4_len, payload_len,
				create_skb_ipv4_udp_frag);
		if (!skb_in)
			goto end;
		break;
	case (L4PROTO_ICMP):
		total_l4_len = total_payload + sizeof(struct icmphdr);
		skb_in = create_frags_4(total_frags, mf_flags, frag_offset, df, total_l4_len, payload_len,
				create_skb_ipv4_icmp_info_frag);
		if (!skb_in)
			goto end;
		break;
	default:
		log_debug("Invalid l4 protocol: %u", l4proto);
		return false;
	}

	/* Translate step SKBs*/
	if (translating_the_packet(&tuple, skb_in, &skb_out) != VER_CONTINUE)
		goto end;

	/* Evaluating SKBs*/
	if (!validate_frags6(skb_out, &tuple, total_frags6, is_first, is_last, frag6_offset, payload6_len,
			payload_offset, total_payload, l4proto))
		goto end;

	kfree_skb_queued(skb_in);
	kfree_skb_queued(skb_out);
	return true;
end:
	kfree_skb_queued(skb_in);
	kfree_skb_queued(skb_out);
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

	if (is_error(translate_packet_init()))
		return -EINVAL;

	/* Checksum tests */
	CALL_TEST(test_post_tcp_csum_6to4(), "Recomputed TCP checksum 6->4");
	CALL_TEST(test_post_udp_csum_6to4(), "Recomputed UDP checksum 6->4");
	CALL_TEST(test_update_csum_4to6(), "Recomputed checksum 4->6");

	/* Misc single function tests */
	CALL_TEST(test_function_has_unexpired_src_route(), "Unexpired source route querier");
	CALL_TEST(test_function_build_id_field(), "Identification builder");
	CALL_TEST(test_function_icmp6_minimum_mtu(), "ICMP6 Minimum MTU function");
	CALL_TEST(test_function_icmp4_to_icmp6_param_prob(), "Param problem function");

	CALL_TEST(test_function_get_traffic_class(), "Get Traffic Class function");
	CALL_TEST(test_function_generate_ipv4_id_nofrag(), "Generate id function (no frag)");
	CALL_TEST(test_function_generate_df_flag(), "Generate DF flag function");
	CALL_TEST(test_function_build_protocol_field(), "Build protocol function");
	CALL_TEST(test_function_has_nonzero_segments_left(), "Segments left indicator function");
	CALL_TEST(test_function_generate_ipv4_id_dofrag(), "Generate id function (frag)");
	CALL_TEST(test_function_icmp4_minimum_mtu(), "ICMP4 Minimum MTU function");

	/* Full packet translation tests */
	CALL_TEST(test_4to6_udp(), "Full translation, 4->6 UDP");
	CALL_TEST(test_4to6_tcp(), "Full translation, 4->6 TCP");
	CALL_TEST(test_4to6_icmp_info(), "Full translation, 4->6 ICMP info");
	CALL_TEST(test_4to6_icmp_error(), "Full translation, 4->6 ICMP error");

	CALL_TEST(test_6to4_udp(), "Full translation, 6->4 UDP");
	CALL_TEST(test_6to4_tcp(), "Full translation, 6->4 TCP");
	CALL_TEST(test_6to4_icmp_info(), "Full translation, 6->4 ICMP info");
	CALL_TEST(test_6to4_icmp_error(), "Full translation, 6->4 ICMP error");

	CALL_TEST(test_multiple_4to6_fragment(), "Translate & fragment");

	CALL_TEST(test_multiple_4to6(L4PROTO_UDP, true), "Full Fragments, 4->6 UDP DF=True");
	CALL_TEST(test_multiple_4to6(L4PROTO_UDP, false), "Full Fragments, 4->6 UDP DF=False");
	CALL_TEST(test_multiple_4to6(L4PROTO_TCP, true), "Full Fragments, 4->6 TCP DF=True");
	CALL_TEST(test_multiple_4to6(L4PROTO_TCP, false), "Full Fragments, 4->6 TCP DF=False");
	CALL_TEST(test_multiple_4to6(L4PROTO_ICMP, true), "Full Fragments, 4->6 ICMP DF=True");
	CALL_TEST(test_multiple_4to6(L4PROTO_ICMP, false), "Full Fragments, 4->6 ICMP DF=False");

	CALL_TEST(test_multiple_6to4(L4PROTO_UDP), "Full Fragments, 6->4 UDP");
	CALL_TEST(test_multiple_6to4(L4PROTO_TCP), "Full Fragments, 6->4 TCP");
	CALL_TEST(test_multiple_6to4(L4PROTO_ICMP), "Full Fragments, 6->4 ICMP");

	CALL_TEST(test_big_multiple_4to6(L4PROTO_UDP, false), "Full Big Fragments, 4->6 UDP DF=false");
	CALL_TEST(test_big_multiple_4to6(L4PROTO_ICMP, false), "Full Big Fragments, 4->6 ICMP DF=false");
	translate_packet_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
