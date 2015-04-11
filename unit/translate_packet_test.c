#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/unit/unit_test.h"
#include "nat64/common/str_utils.h"
#include "nat64/unit/skb_generator.h"
#include "nat64/unit/validator.h"
#include "nat64/unit/types.h"
#include "rfc6145/core.c"
#include "rfc6145/6to4.c"
#include "rfc6145/4to6.c"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_DESCRIPTION("Translating the Packet module test.");

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
	success &= assert_equals_be32(cpu_to_be32(1234), build_id_field(&hdr), "Simple");

	return success;
}

static bool update_config(bool lower_mtu_fail)
{
	struct global_config *config;
	int error;

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return false;
	error = config_clone(config);
	if (error) {
		log_err("Errcode %d while trying to clone the config.", error);
		return false;
	}

	config->atomic_frags.lower_mtu_fail = lower_mtu_fail;
	/*
	 * I'm assuming the default plateaus list has 3 elements or more.
	 * (so I don't have to reallocate mtu_plateaus.)
	 */
	config->mtu_plateaus[0] = 1400;
	config->mtu_plateaus[1] = 1200;
	config->mtu_plateaus[2] = 600;
	config->mtu_plateau_count = 3;

	error = config_set(config);
	if (error) {
		log_err("Errcode %u while trying to set the config.", error);
		return false;
	}

	return true;
}

#define min_mtu(packet, in, out, len) be32_to_cpu(icmp6_minimum_mtu(packet, in, out, len))
static bool test_function_icmp6_minimum_mtu(void)
{
	int i;
	bool success = true;

	if (!update_config(false))
		return false;

	/* Test the bare minimum functionality. */
	success &= assert_equals_u32(21, min_mtu(1, 100, 100, 0), "No hacks, min is packet");
	success &= assert_equals_u32(1, min_mtu(100, 1, 100, 0), "No hacks, min is in");
	success &= assert_equals_u32(21, min_mtu(100, 100, 1, 0), "No hacks, min is out");

	if (!success)
		return false;

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
		return false;

	/* Test hack 2: User wants us to try to improve the failure rate. */
	if (!update_config(true))
		return false;

	success &= assert_equals_u32(1280, min_mtu(1, 2, 2, 0), "Improve rate, min is packet");
	success &= assert_equals_u32(1280, min_mtu(2, 1, 2, 0), "Improve rate, min is in");
	success &= assert_equals_u32(1280, min_mtu(2, 2, 1, 0), "Improve rate, min is out");

	success &= assert_equals_u32(1420, min_mtu(1400, 1500, 1500, 0), "Fail improve rate, packet");
	success &= assert_equals_u32(1400, min_mtu(1500, 1400, 1500, 0), "Fail improve rate, in");
	success &= assert_equals_u32(1420, min_mtu(1500, 1500, 1400, 0), "Fail improve rate, out");

	if (!success)
		return false;

	/* Test both hacks at the same time. */
	success &= assert_equals_u32(1280, min_mtu(0, 700, 700, 1000), "2 hacks, override packet");
	success &= assert_equals_u32(1280, min_mtu(0, 1, 100, 1000), "2 hacks, override in");
	success &= assert_equals_u32(1280, min_mtu(0, 100, 1, 1000), "2 hacks, override out");

	success &= assert_equals_u32(1420, min_mtu(0, 1500, 1500, 1500), "2 hacks, packet/not 1280");
	success &= assert_equals_u32(1400, min_mtu(0, 1400, 1500, 1500), "2 hacks, in/not 1280");
	success &= assert_equals_u32(1420, min_mtu(0, 1500, 1400, 1500), "2 hacks, out/not 1280");

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
	hdr4.icmp4_unused = cpu_to_be32(0x08000000U);
	success &= assert_equals_int(0, icmp4_to_icmp6_param_prob(&hdr4, &hdr6), "func result 1");
	success &= assert_equals_u8(ICMPV6_HDR_FIELD, hdr6.icmp6_code, "code");
	success &= assert_equals_u8(7, be32_to_cpu(hdr6.icmp6_pointer), "pointer");

	hdr4.icmp4_unused = cpu_to_be32(0x05000000U);
	success &= assert_equals_int(-EINVAL, icmp4_to_icmp6_param_prob(&hdr4, &hdr6), "func result 2");

	return success;
}

static bool test_function_generate_ipv4_id_nofrag(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	__be16 attempt_1, attempt_2, attempt_3;
	bool success = true;

	skb = alloc_skb(1500, GFP_ATOMIC);
	if (!skb)
		return false;
	pkt.skb = skb;

	skb_put(skb, 1000);
	attempt_1 = generate_ipv4_id_nofrag(&pkt);
	attempt_2 = generate_ipv4_id_nofrag(&pkt);
	attempt_3 = generate_ipv4_id_nofrag(&pkt);
	/*
	 * At least one of the attempts should be nonzero,
	 * otherwise the random would be sucking major ****.
	 */
	success &= assert_not_equals_be16(0, (attempt_1 | attempt_2 | attempt_3), "Len < 1260");

	skb_put(skb, 260);
	attempt_1 = generate_ipv4_id_nofrag(&pkt);
	attempt_2 = generate_ipv4_id_nofrag(&pkt);
	attempt_3 = generate_ipv4_id_nofrag(&pkt);
	success &= assert_not_equals_be16(0, (attempt_1 | attempt_2 | attempt_3), "Len = 1260");

	skb_put(skb, 200);
	success &= assert_equals_be16(0, generate_ipv4_id_nofrag(&pkt), "Len > 1260");

	kfree_skb(skb);
	return success;
}

static bool test_function_generate_df_flag(void)
{
	struct packet pkt;
	struct sk_buff *skb;
	bool success = true;

	skb = alloc_skb(1500, GFP_ATOMIC);
	if (!skb)
		return false;
	pkt.skb = skb;

	skb_put(skb, 1000);
	success &= assert_equals_u16(0, generate_df_flag(&pkt), "Len < 1260");

	skb_put(skb, 260);
	success &= assert_equals_u16(0, generate_df_flag(&pkt), "Len = 1260");

	skb_put(skb, 200);
	success &= assert_equals_u16(1, generate_df_flag(&pkt), "Len > 1260");

	kfree_skb(skb);
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

	fragment_hdr.identification = cpu_to_be32(0x0000abcdU);
	success &= assert_equals_u16(0xabcd, be16_to_cpu(generate_ipv4_id_dofrag(&fragment_hdr)),
			"No overflow");

	fragment_hdr.identification = cpu_to_be32(0x12345678U);
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

static int count_frags(struct sk_buff *skb)
{
	int i;
	for (i = 0; skb; skb = skb->next)
		i++;
	return i;
}

static bool compare_skbs(struct sk_buff *expected, struct sk_buff *actual)
{
	unsigned char *expected_ptr, *actual_ptr;
	unsigned int i, s, min_len;
	int errors = 0;

	if (!assert_equals_int(count_frags(expected), count_frags(actual), "Fragment count"))
		return false;

	s = 0;
	while (expected && !errors) {
		log_debug("Reviewing packet %u.", s);

		if (!assert_equals_int(expected->len, actual->len, "skb length"))
			errors++;

		expected_ptr = (unsigned char *) skb_network_header(expected);
		actual_ptr = (unsigned char *) skb_network_header(actual);
		min_len = (expected->len < actual->len) ? expected->len : actual->len;

		for (i = 0; i < min_len && errors < 6; i++) {
			if (expected_ptr[i] != actual_ptr[i]) {
				log_err("Packets differ at byte %u. Expected: 0x%x; actual: 0x%x.",
						i, expected_ptr[i], actual_ptr[i]);
				errors++;
			}
		}

		expected = expected->next;
		actual = actual->next;
		s++;
	}

	return !errors;
}

static bool test_4to6(l4_protocol l4_proto,
		int (*create_skb4_fn)(struct tuple *, struct sk_buff **, u16, u8),
		int (*create_skb6_fn)(struct tuple *, struct sk_buff **, u16, u8),
		u16 expected_payload6_len)
{
	struct packet pkt4, pkt6_actual = { .skb = NULL };
	struct sk_buff *skb4 = NULL, *skb6_expected = NULL;
	struct tuple tuple4, tuple6;
	bool result = false;

	if (init_ipv4_tuple(&tuple4, "192.0.2.5", 1234, "192.0.2.2", 80, l4_proto) != 0
			|| init_ipv6_tuple(&tuple6, "64::192.0.2.5", 51234, "1::1", 50080, l4_proto) != 0
			|| create_skb4_fn(&tuple4, &skb4, 100, 32) != 0
			|| create_skb6_fn(&tuple6, &skb6_expected, expected_payload6_len, 31) != 0
			|| pkt_init_ipv4(&pkt4, skb4))
		goto end;

	if (translating_the_packet(&tuple6, &pkt4, &pkt6_actual) != VERDICT_CONTINUE)
		goto end;

	result = compare_skbs(skb6_expected, pkt6_actual.skb);
	/* Fall through. */

end:
	kfree_skb(skb4);
	kfree_skb(skb6_expected);
	kfree_skb(pkt6_actual.skb);
	return result;
}

static bool test_4to6_udp(void)
{
	return test_4to6(L4PROTO_UDP, create_skb4_udp, create_skb6_udp, 100);
}

static bool test_4to6_tcp(void)
{
	return test_4to6(L4PROTO_TCP, create_skb4_tcp, create_skb6_tcp, 100);
}

static bool test_4to6_icmp_info(void)
{
	return test_4to6(L4PROTO_ICMP, create_skb4_icmp_info, create_skb6_icmp_info, 100);
}

static bool test_4to6_icmp_error(void)
{
	return test_4to6(L4PROTO_TCP, create_skb4_icmp_error, create_skb6_icmp_error, 120);
}

static bool test_6to4(l4_protocol l4_proto,
		int (*create_skb6_fn)(struct tuple *, struct sk_buff **, u16, u8),
		int (*create_skb4_fn)(struct tuple *, struct sk_buff **, u16, u8),
		u16 expected_payload4_len)
{
	struct global_config *config;
	struct packet pkt6, pkt4_actual = { .skb = NULL };
	struct sk_buff *skb6 = NULL, *skb4_expected = NULL;
	struct tuple tuple6, tuple4;
	int error;
	bool result = false;

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		goto end;
	error = config_clone(config);
	if (error) {
		log_err("Errcode %d while trying to clone the config.", error);
		goto end;
	}
	config->atomic_frags.df_always_on = true;
	config->atomic_frags.build_ipv4_id = false;
	error = config_set(config);
	if (error) {
		log_err("Errcode %d while trying to set the config.", error);
		goto end;
	}

	if (init_ipv6_tuple(&tuple6, "1::1", 50080, "64::192.0.2.5", 51234, L4PROTO_UDP) != 0
			|| init_ipv4_tuple(&tuple4, "192.0.2.2", 80, "192.0.2.5", 1234, L4PROTO_UDP) != 0
			|| create_skb6_fn(&tuple6, &skb6, 100, 32) != 0
			|| create_skb4_fn(&tuple4, &skb4_expected, expected_payload4_len, 31) != 0
			|| pkt_init_ipv6(&pkt6, skb6))
		goto end;

	if (translating_the_packet(&tuple4, &pkt6, &pkt4_actual) != VERDICT_CONTINUE)
		goto end;

	result = compare_skbs(skb4_expected, pkt4_actual.skb);
	/* Fall through. */

end:
	kfree_skb(skb6);
	kfree_skb(skb4_expected);
	kfree_skb(pkt4_actual.skb);
	return result;
}

static bool test_6to4_custom_payload(l4_protocol l4_proto,
		int (*create_skb6_fn)(struct tuple *, struct sk_buff **, u16 *, u16, u8),
		int (*create_skb4_fn)(struct tuple *, struct sk_buff **, u16 *, u16, u8),
		u16 expected_payload4_len, u16 *payload_array)
{
	struct packet pkt6, pkt4_actual = { .skb = NULL };
	struct sk_buff *skb6 = NULL, *skb4_expected = NULL;
	struct tuple tuple6, tuple4;
	bool result = false;

	if (init_ipv6_tuple(&tuple6, "1::1", 50080, "64::192.0.2.5", 51234, L4PROTO_UDP) != 0
			|| init_ipv4_tuple(&tuple4, "192.0.2.2", 80, "192.0.2.5", 1234, L4PROTO_UDP) != 0
			|| create_skb6_fn(&tuple6, &skb6, payload_array, 4, 32) != 0
			|| create_skb4_fn(&tuple4, &skb4_expected, payload_array, expected_payload4_len, 31) != 0
			|| pkt_init_ipv6(&pkt6, skb6) != 0)
		goto end;

	if (translating_the_packet(&tuple4, &pkt6, &pkt4_actual) != VERDICT_CONTINUE)
		goto end;

	result = compare_skbs(skb4_expected, pkt4_actual.skb);
	if (!result)
		goto end;

	result = assert_equals_csum(~cpu_to_be16(0x0000U), /* ~0x0000 == 0xFFFF */
			pkt_udp_hdr(&pkt4_actual)->check, "checksum test");
	/* Fall through. */

end:
	kfree_skb(skb6);
	kfree_skb(skb4_expected);
	kfree_skb(pkt4_actual.skb);
	return result;
}

static bool test_6to4_udp_custom_payload(void)
{
	u16 payload_array[] = {0, 0, 118, 172};

	return test_6to4_custom_payload(L4PROTO_UDP, create_skb6_upd_custom_payload,
			create_skb4_upd_custom_payload, 4, payload_array);
}

static bool test_6to4_udp(void)
{
	return test_6to4(L4PROTO_UDP, create_skb6_udp, create_skb4_udp, 100);
}

static bool test_6to4_tcp(void)
{
	return test_6to4(L4PROTO_TCP, create_skb6_tcp, create_skb4_tcp, 100);
}

static bool test_6to4_icmp_info(void)
{
	return test_6to4(L4PROTO_ICMP, create_skb6_icmp_info, create_skb4_icmp_info, 100);
}

static bool test_6to4_icmp_error(void)
{
	return test_6to4(L4PROTO_TCP, create_skb6_icmp_error, create_skb4_icmp_error, 80);
}

int init_module(void)
{
	START_TESTS("Translating the Packet");

	if (is_error(config_init(false)))
		return false;
	if (is_error(pool6_init(NULL, 0)))
		return false;

	/* Misc single function tests */
	CALL_TEST(test_function_has_unexpired_src_route(), "Unexpired source route querier");
	CALL_TEST(test_function_build_id_field(), "Identification builder");
	CALL_TEST(test_function_icmp6_minimum_mtu(), "ICMP6 Minimum MTU function");
	CALL_TEST(test_function_icmp4_to_icmp6_param_prob(), "Param problem function");

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

	CALL_TEST(test_6to4_udp_custom_payload(), "zero IPv4-UDP checksums, 6->4 UDP");

	pool6_destroy();
	config_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	/* No code. */
}
