#include <linux/module.h>
#include <linux/printk.h>

#include "nat64/mod/unit_test.h"
#include "translate_packet.c"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alberto Leiva Popper <aleiva@nic.mx>");
MODULE_DESCRIPTION("Tranlating the Packet (IPv4 to IPv6) module test.");

/********************************************
 * Helper stuff.
 ********************************************/
#define UDP_HDR_LEN sizeof(struct udphdr)
#define TCP_HDR_LEN sizeof(struct tcphdr)
#define ICMP_HDR_LEN sizeof(struct icmphdr)
#define FRAG_HDR_LEN sizeof(struct frag_hdr)

static struct tuple get_ip4_tuple(void)
{
	struct tuple result;

	result.src.addr.ipv4.s_addr = cpu_to_be32(0x57613990);
	result.dst.addr.ipv4.s_addr = cpu_to_be32(0x97254347);
	result.src.l4_id = 9797;
	result.dst.l4_id = 7979;

	return result;
}

static struct tuple get_ip6_tuple(void)
{
	struct tuple result;

	result.src.addr.ipv6.s6_addr32[0] = cpu_to_be32(0x01234567);
	result.src.addr.ipv6.s6_addr32[1] = cpu_to_be32(0x89ABCDEF);
	result.src.addr.ipv6.s6_addr32[2] = cpu_to_be32(0x12345678);
	result.src.addr.ipv6.s6_addr32[3] = cpu_to_be32(0x9ABCDEF0);

	result.dst.addr.ipv6.s6_addr32[0] = cpu_to_be32(0x76543210);
	result.dst.addr.ipv6.s6_addr32[1] = cpu_to_be32(0xFEDCBA98);
	result.dst.addr.ipv6.s6_addr32[2] = cpu_to_be32(0x87654321);
	result.dst.addr.ipv6.s6_addr32[3] = cpu_to_be32(0x0FEDCBA9);

	result.src.l4_id = 9797;
	result.dst.l4_id = 7979;

	return result;
}

static bool build_ip4_hdr_udp(void **l3_header, __u16 *l3_hdr_len)
{
	struct iphdr *ip_header = kmalloc(sizeof(struct iphdr), GFP_ATOMIC);
	if (!ip_header) {
		log_warning("Could not allocate a IPv4 header. Gonna fail...");
		return false;
	}

	ip_header->version = 4;
	ip_header->ihl = sizeof(*ip_header) / 4;
	ip_header->tos = 66;
	ip_header->tot_len = cpu_to_be16(sizeof(struct iphdr) + sizeof(struct udphdr) + 4);
	ip_header->id = cpu_to_be16(1234);
	ip_header->frag_off = cpu_to_be16(IP_DF | 0x0675);
	ip_header->ttl = 5;
	ip_header->protocol = IPPROTO_UDP;
	ip_header->check = 0xFAFA;
	ip_header->saddr = cpu_to_be32(0x12345678);
	ip_header->daddr = cpu_to_be32(0xFEDCBA98);

	*l3_header = ip_header;
	*l3_hdr_len = sizeof(*ip_header);
	return true;
}

static bool build_ip4_hdr_tcp(void **l3_header, __u16 *l3_hdr_len)
{
	struct iphdr *hdr;

	if (!build_ip4_hdr_udp(l3_header, l3_hdr_len))
		return false;

	hdr = *l3_header;
	hdr->tot_len = cpu_to_be16(sizeof(struct iphdr) + sizeof(struct tcphdr) + 4);
	hdr->protocol = IPPROTO_TCP;
	return true;
}

static bool build_ip4_hdr_icmp4(void **l3_header, __u16 *l3_hdr_len)
{
	struct iphdr *hdr;

	if (!build_ip4_hdr_udp(l3_header, l3_hdr_len))
		return false;

	hdr = *l3_header;
	hdr->tot_len = cpu_to_be16(sizeof(struct iphdr) + sizeof(struct icmphdr) + 4);
	hdr->protocol = IPPROTO_ICMP;
	return true;
}

static bool build_ip4_hdr_fragment(void **l3_header, __u16 *l3_hdr_len)
{
	struct iphdr *hdr;

	if (!build_ip4_hdr_udp(l3_header, l3_hdr_len))
		return false;

	hdr = *l3_header;
	hdr->frag_off = cpu_to_be16(0x0675);
	return true;
}

static bool build_ip4_hdr_icmp4_embedded(void **l3_header, __u16 *l3_hdr_len)
{
	struct iphdr *hdr;

	if (!build_ip4_hdr_udp(l3_header, l3_hdr_len))
		return false;

	hdr = *l3_header;
	hdr->tot_len = cpu_to_be16(sizeof(struct iphdr) + sizeof(struct icmphdr)
			+ sizeof(struct iphdr) + sizeof(struct udphdr) + 4);
	hdr->protocol = IPPROTO_ICMP;
	return true;
}

static bool build_ip6_hdr_udp(void **l3_header, __u16 *l3_hdr_len)
{
	struct ipv6hdr *hdr = kmalloc(sizeof(struct ipv6hdr), GFP_ATOMIC);
	if (!hdr) {
		log_warning("Could not allocate a IPv6 header. Gonna fail...");
		return false;
	}

	hdr->version = 6;
	hdr->priority = 0xA;
	hdr->flow_lbl[0] = 0x71;
	hdr->flow_lbl[1] = 0x52;
	hdr->flow_lbl[2] = 0x36;
	hdr->payload_len = cpu_to_be16(sizeof(struct udphdr) + 4);
	hdr->nexthdr = NEXTHDR_UDP;
	hdr->hop_limit = 5;
	hdr->saddr.s6_addr32[0] = cpu_to_be32(0x12456378);
	hdr->saddr.s6_addr32[1] = cpu_to_be32(0x9bcdef0a);
	hdr->saddr.s6_addr32[2] = cpu_to_be32(0x0bfedca9);
	hdr->saddr.s6_addr32[3] = cpu_to_be32(0x86574321);
	hdr->daddr.s6_addr32[0] = cpu_to_be32(0x11223344);
	hdr->daddr.s6_addr32[1] = cpu_to_be32(0x55667788);
	hdr->daddr.s6_addr32[2] = cpu_to_be32(0x99aabbcc);
	hdr->daddr.s6_addr32[3] = cpu_to_be32(0xddeeff00);

	*l3_header = hdr;
	*l3_hdr_len = sizeof(*hdr);
	return true;
}

static bool build_ip6_hdr_tcp(void **l3_header, __u16 *l3_hdr_len)
{
	struct ipv6hdr *hdr;

	if (!build_ip6_hdr_udp(l3_header, l3_hdr_len))
		return false;

	hdr = *l3_header;
	hdr->payload_len = cpu_to_be16(sizeof(struct tcphdr) + 4);
	hdr->nexthdr = NEXTHDR_TCP;

	return true;
}

static bool build_ip6_hdr_icmp(void **l3_header, __u16 *l3_hdr_len)
{
	struct ipv6hdr *hdr;

	if (!build_ip6_hdr_udp(l3_header, l3_hdr_len))
		return false;

	hdr = *l3_header;
	hdr->payload_len = cpu_to_be16(sizeof(struct icmp6hdr) + 4);
	hdr->nexthdr = NEXTHDR_ICMP;

	return true;
}

static bool build_ip6_hdr_fragment(void **l3_header, __u16 *l3_hdr_len)
{
	struct ipv6hdr *fixed_hdr = NULL;
	struct frag_hdr *frag_hdr = NULL;
	*l3_header = NULL;

	fixed_hdr = kmalloc(sizeof(*fixed_hdr) + sizeof(*frag_hdr), GFP_ATOMIC);
	if (!fixed_hdr) {
		log_warning("Could not allocate a IPv6+Fragment header. Gonna fail...");
		goto failure;
	}
	if (!build_ip6_hdr_udp(l3_header, l3_hdr_len))
		goto failure;

	memcpy(fixed_hdr, *l3_header, *l3_hdr_len);
	fixed_hdr->payload_len = cpu_to_be16(sizeof(*frag_hdr) + sizeof(struct udphdr) + 4);
	fixed_hdr->nexthdr = NEXTHDR_FRAGMENT;

	frag_hdr = (struct frag_hdr *) (fixed_hdr + 1);
	frag_hdr->nexthdr = NEXTHDR_UDP;
	frag_hdr->reserved = 0;
	frag_hdr->frag_off = cpu_to_be16(16 << 3);
	frag_hdr->identification = cpu_to_be32(385);

	kfree(*l3_header);
	*l3_header = fixed_hdr;
	*l3_hdr_len = sizeof(*fixed_hdr) + sizeof(*frag_hdr);
	return true;

failure:
	kfree(*l3_header);
	*l3_header = NULL;
	kfree(fixed_hdr);
	return false;
}

static bool build_ip6_hdr_embedded(void **l3_header, __u16 *l3_hdr_len)
{
	struct ipv6hdr *hdr;

	if (!build_ip6_hdr_udp(l3_header, l3_hdr_len))
		return false;

	hdr = *l3_header;
	hdr->payload_len = cpu_to_be16(sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr)
			+ sizeof(struct udphdr) + 4);
	hdr->nexthdr = NEXTHDR_ICMP;

	return true;
}

static void build_simple_payload(unsigned char *target)
{
	target[0] = 0x54;
	target[1] = 0x45;
	target[2] = 0x53;
	target[3] = 0x54;
}

static bool build_l3_payload_udp(void **l3_payload, __u16 *l3_payload_len)
{
	struct udphdr *udp_header;

	*l3_payload_len = sizeof(struct udphdr) + 4;
	*l3_payload = kmalloc(*l3_payload_len, GFP_ATOMIC);
	udp_header = *l3_payload;
	if (!udp_header) {
		log_warning("Could not allocate a UDP header + payload. Gonna fail...");
		return false;
	}

	udp_header->source = cpu_to_be16(5883);
	udp_header->dest = cpu_to_be16(9215);
	udp_header->len = cpu_to_be16(*l3_payload_len);
	udp_header->check = cpu_to_be16(0xAFAF);
	build_simple_payload((unsigned char *) (udp_header + 1));

	return true;
}

static bool build_l3_payload_tcp(void **l3_payload, __u16 *l3_payload_len)
{
	struct tcphdr *tcp_header;

	*l3_payload_len = sizeof(struct tcphdr) + 4;
	*l3_payload = kmalloc(*l3_payload_len, GFP_ATOMIC);
	tcp_header = *l3_payload;
	if (!tcp_header) {
		log_warning("Could not allocate a TCP header + payload. Gonna fail...");
		return false;
	}

	tcp_header->source = cpu_to_be16(3885);
	tcp_header->dest = cpu_to_be16(1592);
	tcp_header->seq = cpu_to_be32(112233);
	tcp_header->ack_seq = cpu_to_be32(332211);
	tcp_header->doff = sizeof(*tcp_header) / 4;
	tcp_header->res1 = 0;
	tcp_header->cwr = 0;
	tcp_header->ece = 0;
	tcp_header->urg = 0;
	tcp_header->ack = 1;
	tcp_header->psh = 0;
	tcp_header->rst = 0;
	tcp_header->syn = 0;
	tcp_header->fin = 0;
	tcp_header->window = cpu_to_be16(300);
	tcp_header->check = cpu_to_be16(400);
	tcp_header->urg_ptr = cpu_to_be16(0);
	build_simple_payload((unsigned char *) (tcp_header + 1));

	return true;
}

static bool build_l3_payload_icmp4(void **l3_payload, __u16 *l3_payload_len)
{
	struct icmphdr *icmp4_header;

	*l3_payload_len = sizeof(struct icmphdr) + 4;
	*l3_payload = kmalloc(*l3_payload_len, GFP_ATOMIC);
	icmp4_header = *l3_payload;
	if (!icmp4_header) {
		log_warning("Could not allocate a ICMPv4 header + payload. Gonna fail...");
		return false;
	}

	icmp4_header->type = ICMP_ECHOREPLY;
	icmp4_header->code = 0;
	icmp4_header->checksum = cpu_to_be16(0);
	icmp4_header->un.echo.id = cpu_to_be16(45);
	icmp4_header->un.echo.sequence = cpu_to_be16(54);
	build_simple_payload((unsigned char *) (icmp4_header + 1));

	return true;
}

static bool build_l3_payload_icmp6(void **l3_payload, __u16 *l3_payload_len)
{
	struct icmp6hdr *icmp6_header;

	*l3_payload_len = sizeof(struct icmphdr) + 4;
	*l3_payload = kmalloc(*l3_payload_len, GFP_ATOMIC);
	icmp6_header = *l3_payload;
	if (!icmp6_header) {
		log_warning("Could not allocate a ICMPv6 header + payload. Gonna fail...");
		return false;
	}

	icmp6_header->icmp6_type = ICMPV6_ECHO_REPLY;
	icmp6_header->icmp6_code = 0;
	icmp6_header->icmp6_cksum = cpu_to_be16(0);
	icmp6_header->icmp6_dataun.u_echo.identifier = cpu_to_be16(45);
	icmp6_header->icmp6_dataun.u_echo.sequence = cpu_to_be16(54);
	build_simple_payload((unsigned char *) (icmp6_header + 1));

	return true;
}

static bool build_l3_payload_icmp4_embedded(void **l3_payload, __u16 *l3_payload_len)
{
	struct icmphdr *icmp_header;
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	unsigned char *payload;

	*l3_payload_len = sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 4;
	*l3_payload = kmalloc(*l3_payload_len, GFP_ATOMIC);
	if (!(*l3_payload)) {
		log_warning("Could not allocate a ICMP header + inner packet. Gonna fail...");
		return false;
	}

	icmp_header = *l3_payload;
	ip_header = (struct iphdr *) (icmp_header + 1);
	udp_header = (struct udphdr *) (ip_header + 1);
	payload = (unsigned char *) (udp_header + 1);

	icmp_header->type = ICMP_TIME_EXCEEDED;
	icmp_header->code = 0;
	icmp_header->checksum = cpu_to_be16(0);
	icmp_header->icmp4_unused = cpu_to_be32(0);

	ip_header->version = 4;
	ip_header->ihl = sizeof(*ip_header) / 4;
	ip_header->tos = 66;
	ip_header->tot_len = cpu_to_be16(sizeof(struct iphdr) + sizeof(struct udphdr) + 4);
	ip_header->id = cpu_to_be16(1234);
	ip_header->frag_off = cpu_to_be16(IP_DF | 0x0675);
	ip_header->ttl = 0;
	ip_header->protocol = IPPROTO_UDP;
	ip_header->check = 0xFAFA;
	ip_header->saddr = cpu_to_be32(0x12345678);
	ip_header->daddr = cpu_to_be32(0xFEDCBA98);

	udp_header->source = cpu_to_be16(1472);
	udp_header->dest = cpu_to_be16(2741);
	udp_header->len = cpu_to_be16(sizeof(struct udphdr) + 4);
	udp_header->check = cpu_to_be16(0xAFAF);

	build_simple_payload(payload);

	return true;
}

static bool build_l3_payload_icmp6_embedded(void **l3_payload, __u16 *l3_payload_len)
{
	struct icmp6hdr *icmp6_header;
	struct ipv6hdr *ip6_header;
	struct udphdr *udp_header;
	unsigned char *payload;

	*l3_payload_len = sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + 4;
	*l3_payload = kmalloc(*l3_payload_len, GFP_ATOMIC);
	if (!(*l3_payload)) {
		log_warning("Could not allocate a payload. Gonna fail...");
		return false;
	}

	icmp6_header = *l3_payload;
	ip6_header = (struct ipv6hdr *) (icmp6_header + 1);
	udp_header = (struct udphdr *) (ip6_header + 1);
	payload = (unsigned char *) (udp_header + 1);

	icmp6_header->icmp6_type = ICMPV6_TIME_EXCEED;
	icmp6_header->icmp6_code = 0;
	icmp6_header->icmp6_cksum = cpu_to_be16(0);
	icmp6_header->icmp6_unused = 0;

	ip6_header->version = 6;
	ip6_header->priority = 0xA;
	ip6_header->flow_lbl[0] = 0x71;
	ip6_header->flow_lbl[1] = 0x52;
	ip6_header->flow_lbl[2] = 0x36;
	ip6_header->payload_len = cpu_to_be16(sizeof(struct udphdr) + 4);
	ip6_header->nexthdr = NEXTHDR_UDP;
	ip6_header->hop_limit = 5;
	ip6_header->saddr.s6_addr32[0] = cpu_to_be32(0x12456378);
	ip6_header->saddr.s6_addr32[1] = cpu_to_be32(0x9bcdef0a);
	ip6_header->saddr.s6_addr32[2] = cpu_to_be32(0x0bfedca9);
	ip6_header->saddr.s6_addr32[3] = cpu_to_be32(0x86574321);
	ip6_header->daddr.s6_addr32[0] = cpu_to_be32(0x11223344);
	ip6_header->daddr.s6_addr32[1] = cpu_to_be32(0x55667788);
	ip6_header->daddr.s6_addr32[2] = cpu_to_be32(0x99aabbcc);
	ip6_header->daddr.s6_addr32[3] = cpu_to_be32(0xddeeff00);

	udp_header->source = cpu_to_be16(3692);
	udp_header->dest = cpu_to_be16(2963);
	udp_header->len = cpu_to_be16(8 + 4);
	udp_header->check = cpu_to_be16(0xAFAF);

	build_simple_payload(payload);

	return true;
}

static struct sk_buff *build_test_skb(bool (*l3_hdr_function)(void **, __u16 *),
		bool (*l3_payload_function)(void **, __u16 *))
{
	void *l3_hdr = NULL, *l3_payload = NULL;
	__u16 l3_hdr_len, l3_payload_len;

	struct sk_buff *skb = NULL;

	if (!l3_hdr_function(&l3_hdr, &l3_hdr_len))
		goto error;
	if (!l3_payload_function(&l3_payload, &l3_payload_len))
		goto error;

	skb = alloc_skb(LL_MAX_HEADER + l3_hdr_len + l3_payload_len, GFP_ATOMIC);
	if (!skb) {
		log_warning("Could not allocate a test packet.");
		goto error;
	}

	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, l3_hdr_len + l3_payload_len);
	skb_set_network_header(skb, 0);
	skb_set_transport_header(skb, l3_hdr_len);

	memcpy(skb_network_header(skb), l3_hdr, l3_hdr_len);
	memcpy(skb_transport_header(skb), l3_payload, l3_payload_len);

	kfree(l3_hdr);
	kfree(l3_payload);
	return skb;

error:
	kfree(l3_hdr);
	kfree(l3_payload);
	return NULL;
}

static bool translate(bool (*l3_hdr_function)(void **, __u16 *),
		bool (*l3_payload_function)(void **, __u16 *),
		struct tuple (*tuple_function)(void),
		bool (*translate_packet_function)(struct tuple *, struct sk_buff *, struct sk_buff **),
		bool (*fixed_hdr_validate_function)(void *),
		bool (*frag_hdr_validate_function)(struct frag_hdr *),
		bool (*l4_validate_function)(void *l4_hdr))
{
	// Init.
	struct sk_buff *packet_in = build_test_skb(l3_hdr_function, l3_payload_function);
	struct sk_buff *packet_out = NULL;
	struct tuple tuple_in = tuple_function();

	if (!packet_in)
		goto error;

	// Execute.
	if (!translate_packet_function(&tuple_in, packet_in, &packet_out))
		goto error;

	// Validate.
	if (packet_out == NULL) {
		log_warning("The translate packet function returned success but its packet is NULL.");
		goto error;
	}

	if (!fixed_hdr_validate_function(skb_network_header(packet_out)))
		goto error;
	if (!frag_hdr_validate_function((struct frag_hdr *) (ipv6_hdr(packet_out) + 1)))
		goto error;
	if (!l4_validate_function(skb_transport_header(packet_out)))
		goto error;

	// Quit.
	kfree_skb(packet_in);
	kfree_skb(packet_out);
	return true;

error:
	kfree_skb(packet_in);
	kfree_skb(packet_out);
	return false;
}

static bool validate_ip6_fixed_hdr_common(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;
	struct tuple dummy_tuple = get_ip6_tuple();
	bool success = true;

	success &= assert_equals_u8(6, hdr->version, "Version");
	// 66 = 0x42.
	success &= assert_equals_u8(4, hdr->priority, "Traffic class");
	success &= assert_equals_u8(2 << 4, hdr->flow_lbl[0], "Flow label (0)");
	success &= assert_equals_u8(0, hdr->flow_lbl[1], "Flow label (1)");
	success &= assert_equals_u8(0, hdr->flow_lbl[2], "Flow label (2)");
	// success &= assert_equals_u16(, be16_to_cpu(hdr->payload_len), "Payload len");
	// success &= assert_equals_u8(, hdr->nexthdr, "Next header");
	// success &= assert_equals_u8(5, hdr->hop_limit, "Hop limit");
	success &= assert_equals_ipv6(&dummy_tuple.src.addr.ipv6, &hdr->saddr, "Source address");
	success &= assert_equals_ipv6(&dummy_tuple.dst.addr.ipv6, &hdr->daddr, "Dest address");

	return success;
}

static bool validate_ip6_fixed_hdr_udp_nofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;
	bool success = true;

	success &= validate_ip6_fixed_hdr_common(ip6_header);
	// udp hdr + payload.
	success &= assert_equals_u16(8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	success &= assert_equals_u8(IPPROTO_UDP, hdr->nexthdr, "Next header");
	success &= assert_equals_u8(5, hdr->hop_limit, "Hop limit");

	return success;
}

static bool validate_ip6_fixed_hdr_tcp_nofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;
	bool success = true;

	success &= validate_ip6_fixed_hdr_common(ip6_header);
	// tcp hdr + payload.
	success &= assert_equals_u16(20 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	success &= assert_equals_u8(IPPROTO_TCP, hdr->nexthdr, "Next header");
	success &= assert_equals_u8(5, hdr->hop_limit, "Hop limit");

	return success;
}

static bool validate_ip6_fixed_hdr_icmp_nofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;
	bool success = true;

	success &= validate_ip6_fixed_hdr_common(ip6_header);
	// icmpv6 hdr + payload.
	success &= assert_equals_u16(8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	success &= assert_equals_u8(NEXTHDR_ICMP, hdr->nexthdr, "Next header");
	success &= assert_equals_u8(5, hdr->hop_limit, "Hop limit");

	return success;
}

static bool validate_ip6_fixed_hdr_icmp_embedded(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;
	bool success = true;

	success &= validate_ip6_fixed_hdr_common(ip6_header);
	// icmp hdr + ipv6 hdr + udp hdr + payload.
	success &= assert_equals_u16(8 + 40 + 8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	success &= assert_equals_u8(NEXTHDR_ICMP, hdr->nexthdr, "Next header");
	success &= assert_equals_u8(5, hdr->hop_limit, "Hop limit");

	return success;
}

static bool validate_ip6_fixed_hdr_udp_dofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;
	bool success = true;

	success &= validate_ip6_fixed_hdr_common(ip6_header);
	// frag hdr + udp hdr + payload.
	success &= assert_equals_u16(8 + 8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	success &= assert_equals_u8(NEXTHDR_FRAGMENT, hdr->nexthdr, "Next header");
	success &= assert_equals_u8(5, hdr->hop_limit, "Hop limit");

	return success;
}

static bool validate_ip6_frag_hdr_nofrag(struct frag_hdr *frag_header)
{
	return true;
}

static bool validate_ip6_frag_hdr_dofrag(struct frag_hdr *frag_header)
{
	bool success = true;

	success &= assert_equals_u8(IPPROTO_UDP, frag_header->nexthdr, "Frag hdr's next header");
	success &= assert_equals_u8(0, frag_header->reserved, "Frag hdr's reserved");
	success &= assert_equals_u16(0x0675 << 3, be16_to_cpu(frag_header->frag_off),
			"Frag hdr's fragment offset");
	success &= assert_equals_u32(1234, be32_to_cpu(frag_header->identification),
			"Frag hdr's identification");

	return success;
}

static bool validate_ip4_hdr_common(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	struct tuple dummy_tuple = get_ip4_tuple();
	bool success = true;

	struct in_addr src, dst;
	src.s_addr = hdr->saddr;
	dst.s_addr = hdr->daddr;

	success &= assert_equals_u8(4, hdr->version, "Version");
	success &= assert_equals_u8(5, hdr->ihl, "Internet Header Length");
	success &= assert_equals_u8(0xA7, hdr->tos, "Type of Service");
	// success &= assert_equals(, be16_to_cpu(hdr->tot_len), "Total Length");
	success &= assert_equals_u16(0, be16_to_cpu(hdr->id), "Identification");
	success &= assert_equals_u16(IP_DF, be16_to_cpu(hdr->frag_off), "Flags & Fragment Offset");
	success &= assert_equals_u8(5, hdr->ttl, "Time to Live");
	// success &= assert_equals(, hdr->protocol, "Protocol");
	// success &= assert_equals(, hdr->check, "Header Checksum");
	success &= assert_equals_ipv4(&dummy_tuple.src.addr.ipv4, &src, "Source address");
	success &= assert_equals_ipv4(&dummy_tuple.dst.addr.ipv4, &dst, "Dest address");

	return success;
}

static bool validate_ip4_hdr_udp(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	bool success = true;

	success &= validate_ip4_hdr_common(l3_hdr);
	// iphdr + udphdr + 4
	success &= assert_equals_u16(20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	success &= assert_equals_u8(IPPROTO_UDP, hdr->protocol, "Protocol");

	return success;
}

static bool validate_ip4_hdr_tcp(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	bool success = true;

	success &= validate_ip4_hdr_common(l3_hdr);
	// iphdr + tcphdr + 4
	success &= assert_equals_u16(20 + 20 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	success &= assert_equals_u8(IPPROTO_TCP, hdr->protocol, "Protocol");

	return success;
}

static bool validate_ip4_hdr_icmp4(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	bool success = true;

	success &= validate_ip4_hdr_common(l3_hdr);
	// iphdr + icmphdr + 4
	success &= assert_equals_u16(20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	success &= assert_equals_u8(IPPROTO_ICMP, hdr->protocol, "Protocol");

	return success;
}

static bool validate_ip4_hdr_fragment(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	struct tuple dummy_tuple = get_ip4_tuple();
	bool success = true;

	struct in_addr src, dst;
	src.s_addr = hdr->saddr;
	dst.s_addr = hdr->daddr;

	success &= assert_equals_u8(4, hdr->version, "Version");
	success &= assert_equals_u8(5, hdr->ihl, "Internet Header Length");
	success &= assert_equals_u8(0xA7, hdr->tos, "Type of Service");
	// iphdr + udphdr + payload.
	success &= assert_equals_u16(20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	success &= assert_equals_u16(385, be16_to_cpu(hdr->id), "Identification"); //
	success &= assert_equals_u16(16, be16_to_cpu(hdr->frag_off), "Flags & Fragment Offset"); //
	success &= assert_equals_u8(5, hdr->ttl, "Time to Live");
	success &= assert_equals_u8(IPPROTO_UDP, hdr->protocol, "Protocol"); //
	// success &= assert_equals(, hdr->check, "Header Checksum");
	success &= assert_equals_ipv4(&dummy_tuple.src.addr.ipv4, &src, "Source address");
	success &= assert_equals_ipv4(&dummy_tuple.dst.addr.ipv4, &dst, "Dest address");

	return success;
}

static bool validate_ip4_hdr_embedded(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	bool success = true;

	success &= validate_ip4_hdr_common(l3_hdr);
	// iphdr + icmphdr + iphdr + udphdr + 4
	success &= assert_equals_u16(20 + 8 + 20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	success &= assert_equals_u8(IPPROTO_ICMP, hdr->protocol, "Protocol");

	return success;
}

static bool validate_simple_payload(unsigned char *payload)
{
	bool success = true;

	success &= assert_equals_u8(0x54, payload[0], "Payload, first chara");
	success &= assert_equals_u8(0x45, payload[1], "Payload, second chara");
	success &= assert_equals_u8(0x53, payload[2], "Payload, third chara");
	success &= assert_equals_u8(0x54, payload[3], "Payload, fourth chara");

	return success;
}

static bool validate_l3_payload_udp(void *l4_hdr)
{
	struct udphdr *udp_header = l4_hdr;
	bool success = true;

	success &= assert_equals_u16(9797, be16_to_cpu(udp_header->source), "UDP source port");
	success &= assert_equals_u16(7979, be16_to_cpu(udp_header->dest), "UDP dest port");
	success &= assert_equals_u16(8 + 4, be16_to_cpu(udp_header->len), "UDP length");
	// success &= assert_equals_u16(0xAFAF, be16_to_cpu(udp_header->check), "UDP checksum");

	success &= validate_simple_payload((unsigned char *) (udp_header + 1));

	return success;
}

static bool validate_l3_payload_tcp(void *l4_hdr)
{
	struct tcphdr *tcp_header = l4_hdr;
	bool success = true;

	success &= assert_equals_u16(9797, be16_to_cpu(tcp_header->source), "Source port");
	success &= assert_equals_u16(7979, be16_to_cpu(tcp_header->dest), "Dest port");
	success &= assert_equals_u32(112233, be32_to_cpu(tcp_header->seq), "Seq number");
	success &= assert_equals_u32(332211, be32_to_cpu(tcp_header->ack_seq), "ACK number");
	success &= assert_equals_u8(5, tcp_header->doff, "Data offset");
	success &= assert_equals_u8(0, tcp_header->res1, "Reserved & NS");
	success &= assert_equals_u8(0, tcp_header->cwr, "CWR");
	success &= assert_equals_u8(0, tcp_header->ece, "ECE");
	success &= assert_equals_u8(0, tcp_header->urg, "URG");
	success &= assert_equals_u8(1, tcp_header->ack, "ACK");
	success &= assert_equals_u8(0, tcp_header->psh, "PSH");
	success &= assert_equals_u8(0, tcp_header->rst, "RST");
	success &= assert_equals_u8(0, tcp_header->syn, "SYN");
	success &= assert_equals_u8(0, tcp_header->fin, "FIN");
	success &= assert_equals_u16(300, be16_to_cpu(tcp_header->window), "Window size");
	// success &= assert_equals(, tcp_header->check, "Checksum");
	success &= assert_equals_u16(0, be16_to_cpu(tcp_header->urg_ptr), "Urgent pointer");

	return success;
}

static bool validate_l3_payload_icmp4_simple(void *l4_hdr)
{
	struct icmphdr *icmp4_header = l4_hdr;
	bool success = true;

	success &= assert_equals_u8(ICMP_ECHOREPLY, icmp4_header->type, "Type");
	success &= assert_equals_u8(0, icmp4_header->code, "Code");
	// success &= assert_equals(, icmp4_header->checksum, "Checksum");
	// The one from the tuple has to everride the one from the packet.
	success &= assert_equals_u16(9797, be16_to_cpu(icmp4_header->un.echo.id), "Echo ID");
	success &= assert_equals_u16(54, be16_to_cpu(icmp4_header->un.echo.sequence), "Echo seq");

	return success;
}

static bool validate_l3_payload_icmp4_embedded(void *l4_hdr)
{
	struct icmphdr *icmp4_header = l4_hdr;
	struct iphdr *ip4_header = (struct iphdr *) (icmp4_header + 1);
	struct udphdr *udp_header = (struct udphdr *) (ip4_header + 1);
	bool success = true;

	success &= assert_equals_u8(ICMP_TIME_EXCEEDED, icmp4_header->type, "ICMP Type");
	success &= assert_equals_u8(0, icmp4_header->code, "ICMP Code");
	// success &= assert_equals(, icmp4_header->checksum, "ICMP Checksum");
	success &= assert_equals_u32(0, be32_to_cpu(icmp4_header->un.gateway), "ICMP Unused");

	success &= validate_ip4_hdr_common(ip4_header);
	// That the code writes garbage in both the inner tot_len and the checksum is a known quirk.
	// The inner packet is usually minced so nobody should trust those fields.
	// success &= assert_equals_u16(iphdr + udphdr + 4, be16_to_cpu(ip4_header->tot_len),
	// 		"Inner total Length");
	success &= assert_equals_u8(IPPROTO_UDP, ip4_header->protocol, "Inner protocol");
	// success &= assert_equals_u16(iphdr + udphdr + 4, be16_to_cpu(ip4_header->tot_len),
	// 		"Inner checksum");

	success &= assert_equals_u16(3692, be16_to_cpu(udp_header->source), "Inner source port");
	success &= assert_equals_u16(2963, be16_to_cpu(udp_header->dest), "Inner dest port");
	success &= assert_equals_u16(8 + 4, be16_to_cpu(udp_header->len), "Inner UDP length");
	// success &= assert_equals_u16(0xAFAF, be16_to_cpu(udp_header->check), "Inner UDP checksum");

	success &= validate_simple_payload((unsigned char *) (udp_header + 1));

	return success;
}

static bool validate_l3_payload_icmp6_simple(void *l4_hdr)
{
	struct icmp6hdr *hdr = l4_hdr;
	bool success = true;

	success &= assert_equals_u8(ICMPV6_ECHO_REPLY, hdr->icmp6_type, "ICMP type");
	success &= assert_equals_u8(0, hdr->icmp6_code, "ICMP code");
	// success &= assert_equals(6, hdr->icmp6_cksum, "ICMP checksum");
	// The one from the tuple has to everride the one from the packet.
	success &= assert_equals_u16(9797, be16_to_cpu(hdr->icmp6_dataun.u_echo.identifier),
			"ICMP echo reply id");
	success &= assert_equals_u16(54, be16_to_cpu(hdr->icmp6_dataun.u_echo.sequence),
			"ICMP echo reply seq");

	return success;
}

static bool validate_l3_payload_icmp6_embedded(void *l4_hdr)
{
	struct icmp6hdr *icmp6_header = l4_hdr;
	struct ipv6hdr *ip6_header = (struct ipv6hdr *) (icmp6_header + 1);
	struct udphdr *udp_header = (struct udphdr *) (ip6_header + 1);
	bool success = true;

	success &= assert_equals_u8(ICMPV6_TIME_EXCEED, icmp6_header->icmp6_type, "ICMP type");
	success &= assert_equals_u8(0, icmp6_header->icmp6_code, "ICMP code");
	// success &= assert_equals(6, icmp6_header->icmp6_cksum, "ICMP checksum");
	success &= assert_equals_u32(0, be32_to_cpu(icmp6_header->icmp6_unused), "ICMP unused");

	success &= validate_ip6_fixed_hdr_common(ip6_header);
	// That the code writes garbage in both the inner payload_len and the checksum is a known quirk.
	// The inner packet is usually minced so nobody should trust those fields.
	// success &= assert_equals(udp hdr + payload, be16_to_cpu(ip6_header->payload_len),
	// 		"Inner payload len");
	success &= assert_equals_u8(IPPROTO_UDP, ip6_header->nexthdr, "Inner next header");
	success &= assert_equals_u8(0, ip6_header->hop_limit, "Inner hop limit");

	success &= assert_equals_u16(1472, be16_to_cpu(udp_header->source), "Inner source port");
	success &= assert_equals_u16(2741, be16_to_cpu(udp_header->dest), "Inner dest port");
	success &= assert_equals_u16(8 + 4, be16_to_cpu(udp_header->len), "Inner UDP length");
	// success &= assert_equals_u16(0xAFAF, be16_to_cpu(udp_header->check), "Inner UDP checksum");

	success &= validate_simple_payload((unsigned char *) (udp_header + 1));

	return success;
}

/********************************************
 * Tests.
 ********************************************/

static bool test_function_is_dont_fragment_set(void)
{
	struct iphdr hdr;
	bool success = true;

	hdr.frag_off = cpu_to_be16(0x0000);
	success &= assert_equals_u16(0, is_dont_fragment_set(&hdr), "All zeroes");

	hdr.frag_off = cpu_to_be16(0x4000);
	success &= assert_equals_u16(1, is_dont_fragment_set(&hdr), "All zeroes except DF");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	success &= assert_equals_u16(1, is_dont_fragment_set(&hdr), "All ones");

	hdr.frag_off = cpu_to_be16(0xBFFF);
	success &= assert_equals_u16(0, is_dont_fragment_set(&hdr), "All ones except DF");

	return success;
}

static bool test_function_is_more_fragments_set(void)
{
	struct iphdr hdr;
	bool success = true;

	hdr.frag_off = cpu_to_be16(0x0000);
	success &= assert_equals_u16(0, is_more_fragments_set(&hdr), "All zeroes");

	hdr.frag_off = cpu_to_be16(0x2000);
	success &= assert_equals_u16(1, is_more_fragments_set(&hdr), "All zeroes except MF");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	success &= assert_equals_u16(1, is_more_fragments_set(&hdr), "All ones");

	hdr.frag_off = cpu_to_be16(0xDFFF);
	success &= assert_equals_u16(0, is_more_fragments_set(&hdr), "All ones except MF");

	return success;
}

static bool test_function_has_unexpired_src_route(void)
{
	struct iphdr *hdr = kmalloc(60, GFP_ATOMIC); // 60 is the max value allowed by hdr.ihl.
	unsigned char *options;
	bool success = true;

	if (!hdr) {
		log_warning("Can't allocate a test header.");
		return false;
	}
	options = (unsigned char *) (hdr + 1);

	hdr->ihl = 5; // min legal value.
	success &= assert_false(has_unexpired_src_route(hdr), "No options");

	hdr->ihl = 6;
	options[0] = IPOPT_SID;
	options[1] = 4;
	options[2] = 0xAB;
	options[3] = 0xCD;
	success = assert_false(has_unexpired_src_route(hdr), "No source route option, simple");

	hdr->ihl = 9;
	options[0] = IPOPT_RR; // Record route option
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
	options[11] = IPOPT_NOOP; // No operation option.
	options[12] = IPOPT_NOOP; // No operation option.
	options[13] = IPOPT_END; // End of options list option.
	// Leave the rest as garbage.
	success &= assert_false(has_unexpired_src_route(hdr), "No source option, multiple options");

	hdr->ihl = 9;
	options[0] = IPOPT_LSRR;
	options[1] = 15;
	options[2] = 16;
	options[3] = 0x11; // First address
	options[4] = 0x11;
	options[5] = 0x11;
	options[6] = 0x11;
	options[7] = 0x22; // Second address
	options[8] = 0x22;
	options[9] = 0x22;
	options[10] = 0x22;
	options[11] = 0x33; // Third address
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
	options[8] = 0x11; // First address
	options[9] = 0x11;
	options[10] = 0x11;
	options[11] = 0x11;
	options[12] = 0x22; // Second address
	options[13] = 0x22;
	options[14] = 0x22;
	options[15] = 0x22;
	options[16] = 0x33; // Third address
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

static bool test_function_build_ipv6_frag_off_field(void)
{
	struct iphdr hdr;
	bool success = true;

	// 0x32E9 = 001 1001011101001
	hdr.frag_off = cpu_to_be16(0x32E9);
	// 0x9749 = 1001011101001 001
	success &= assert_equals_u16(cpu_to_be16(0x9749), build_ipv6_frag_off_field(&hdr),
			"More fragments on.");

	// 0xD15A = 110 1000101011010
	hdr.frag_off = cpu_to_be16(0xD15A);
	// 0x8AD0 = 1000101011010 000
	success &= assert_equals_u16(cpu_to_be16(0x8AD0), build_ipv6_frag_off_field(&hdr),
			"More fragments off.");

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

#define min_mtu(packet, in, out, len) be16_to_cpu(icmp6_minimum_mtu(packet, in, out, len))
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

	// Test the bare minimum functionality.
	success &= assert_equals_u16(1, min_mtu(1, 2, 2, 0), "No hacks, min is packet");
	success &= assert_equals_u16(1, min_mtu(2, 1, 2, 0), "No hacks, min is in");
	success &= assert_equals_u16(1, min_mtu(2, 2, 1, 0), "No hacks, min is out");

	if (!success)
		goto revert;

	// Test hack 1: MTU is overriden if some router set is as zero.
	for (i = 1500; i > 1400; --i)
		success &= assert_equals_u16(1400, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 1400; i > 1200; --i)
		success &= assert_equals_u16(1200, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 1200; i > 600; --i)
		success &= assert_equals_u16(600, min_mtu(0, 1600, 1600, i), "Override packet MTU");
	for (i = 600; i > 0; --i)
		success &= assert_equals_u16(0, min_mtu(0, 1600, 1600, i), "Override packet MTU");

	success &= assert_equals_u16(1, min_mtu(0, 1, 2, 1000), "Override packet MTU, min is in");
	success &= assert_equals_u16(1, min_mtu(0, 2, 1, 1000), "Override packet MTU, min is out");

	if (!success)
		goto revert;

	// Test hack 2: User wants us to try to improve the failure rate.
	config.lower_mtu_fail = true;

	success &= assert_equals_u16(1280, min_mtu(1, 2, 2, 0), "Improve rate, min is packet");
	success &= assert_equals_u16(1280, min_mtu(2, 1, 2, 0), "Improve rate, min is in");
	success &= assert_equals_u16(1280, min_mtu(2, 2, 1, 0), "Improve rate, min is out");

	success &= assert_equals_u16(1300, min_mtu(1300, 1400, 1400, 0), "Fail improve rate, packet");
	success &= assert_equals_u16(1300, min_mtu(1400, 1300, 1400, 0), "Fail improve rate, in");
	success &= assert_equals_u16(1300, min_mtu(1400, 1400, 1300, 0), "Fail improve rate, out");

	if (!success)
		goto revert;

	// Test both hacks at the same time.
	success &= assert_equals_u16(1280, min_mtu(0, 700, 700, 1000), "2 hacks, override packet");
	success &= assert_equals_u16(1280, min_mtu(0, 1, 2, 1000), "2 hacks, override in");
	success &= assert_equals_u16(1280, min_mtu(0, 2, 1, 1000), "2 hacks, override out");

	success &= assert_equals_u16(1400, min_mtu(0, 1500, 1500, 1401), "2 hacks, packet/not 1280");
	success &= assert_equals_u16(1400, min_mtu(0, 1400, 1500, 1501), "2 hacks, in/not 1280");
	success &= assert_equals_u16(1400, min_mtu(0, 1500, 1400, 1501), "2 hacks, out/not 1280");

	// Fall through.
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
	__u8 ipv6_header[4]; // We don't really need the rest of the bytes.
	bool success = true;

	// version: 2 (Yes, it's not 6. Doesn't matter.)
	// traffic class: ce
	// flow label: 3c3e0
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

	hdr.payload_len = cpu_to_be16(4); // packet length is 44.
	success &= assert_equals_u16(0, generate_ipv4_id_nofrag(&hdr), "Length < 88 bytes");

	hdr.payload_len = cpu_to_be16(48); // packet length is 88.
	success &= assert_equals_u16(0, generate_ipv4_id_nofrag(&hdr), "Length = 88 bytes");

	hdr.payload_len = cpu_to_be16(500); // packet length is 540.
	attempt_1 = generate_ipv4_id_nofrag(&hdr);
	attempt_2 = generate_ipv4_id_nofrag(&hdr);
	attempt_3 = generate_ipv4_id_nofrag(&hdr);
	// At least one of the attempts should be nonzero,
	// otherwise the random would be sucking major ****.
	success &= assert_not_equals_u16(0, (attempt_1 | attempt_2 | attempt_3), "88 < Len < 1280");

	hdr.payload_len = cpu_to_be16(1240); // packet length is 1280.
	attempt_1 = generate_ipv4_id_nofrag(&hdr);
	attempt_2 = generate_ipv4_id_nofrag(&hdr);
	attempt_3 = generate_ipv4_id_nofrag(&hdr);
	success &= assert_not_equals_u16(0, (attempt_1 | attempt_2 | attempt_3), "Len = 1280");

	hdr.payload_len = cpu_to_be16(4000); // packet length is 4040.
	success &= assert_equals_u16(0, generate_ipv4_id_nofrag(&hdr), "Len > 1280");

	return success;
}

static bool test_function_generate_df_flag(void)
{
	struct ipv6hdr hdr;
	bool success = true;

	hdr.payload_len = cpu_to_be16(4); // packet length is 44.
	success &= assert_equals_u16(1, generate_df_flag(&hdr), "Length < 88 bytes");

	hdr.payload_len = cpu_to_be16(48); // packet length is 88.
	success &= assert_equals_u16(1, generate_df_flag(&hdr), "Length = 88 bytes");

	hdr.payload_len = cpu_to_be16(500); // packet length is 540.
	success &= assert_equals_u16(0, generate_df_flag(&hdr), "88 < Len < 1280");

	hdr.payload_len = cpu_to_be16(1240); // packet length is 1280.
	success &= assert_equals_u16(0, generate_df_flag(&hdr), "Len = 1280");

	hdr.payload_len = cpu_to_be16(4000); // packet length is 4040.
	success &= assert_equals_u16(1, generate_df_flag(&hdr), "Len > 1280");

	return success;
}

static bool test_function_build_ipv4_frag_off_field(void)
{
	bool success = true;

	success &= assert_equals_u16(0x407b, be16_to_cpu(build_ipv4_frag_off_field(1, 0, 123)),
			"Simple 1");
	success &= assert_equals_u16(0x2159, be16_to_cpu(build_ipv4_frag_off_field(0, 1, 345)),
			"Simple 2");

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

	// Just ICMP.
	ip6_hdr->nexthdr = NEXTHDR_ICMP;
	ip6_hdr->payload_len = cpu_to_be16(sizeof(*icmp6_hdr));
	if (!assert_equals_u8(IPPROTO_ICMP, build_protocol_field(ip6_hdr), "Just ICMP"))
		goto failure;

	// Skippable headers then ICMP.
	ip6_hdr->nexthdr = NEXTHDR_HOP;
	ip6_hdr->payload_len = cpu_to_be16(8 + 16 + 24 + sizeof(*icmp6_hdr));

	hop_by_hop_hdr = (struct ipv6_opt_hdr *) (ip6_hdr + 1);
	hop_by_hop_hdr->nexthdr = NEXTHDR_ROUTING;
	hop_by_hop_hdr->hdrlen = 0; // the hdrlen field does not include the first 8 octets.

	routing_hdr = (struct ipv6_opt_hdr *) (((unsigned char *) hop_by_hop_hdr) + 8);
	routing_hdr->nexthdr = NEXTHDR_DEST;
	routing_hdr->hdrlen = 1;

	dest_options_hdr = (struct ipv6_opt_hdr *) (((unsigned char *) routing_hdr) + 16);
	dest_options_hdr->nexthdr = NEXTHDR_ICMP;
	dest_options_hdr->hdrlen = 2;

	if (!assert_equals_u8(IPPROTO_ICMP, build_protocol_field(ip6_hdr), "Skippable then ICMP"))
		goto failure;

	// Skippable headers then something else.
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

	ip6_hdr = kmalloc(sizeof(*ip6_hdr) + sizeof(*routing_hdr), GFP_ATOMIC);
	if (!ip6_hdr) {
		log_warning("Could not allocate a test packet.");
		return false;
	}

	// No extension headers.
	ip6_hdr->nexthdr = NEXTHDR_TCP;
	success &= assert_false(has_nonzero_segments_left(ip6_hdr, &offset), "No extension headers");

	if (!success)
		goto end;

	// Routing header with nonzero segments left.
	ip6_hdr->nexthdr = NEXTHDR_ROUTING;
	routing_hdr = (struct ipv6_rt_hdr *) (ip6_hdr + 1);
	routing_hdr->segments_left = 12;
	success &= assert_true(has_nonzero_segments_left(ip6_hdr, &offset), "Nonzero left - result");
	success &= assert_equals_u32(40 + 3, offset, "Nonzero left - offset");

	if (!success)
		goto end;

	// Routing header with zero segments left.
	routing_hdr->segments_left = 0;
	success &= assert_false(has_nonzero_segments_left(ip6_hdr, &offset), "Zero left");

	if (!success)
		goto end;

	// Fragment header, then routing header with nonzero segments left
	// (further test the out parameter).
	ip6_hdr->nexthdr = NEXTHDR_FRAGMENT;
	fragment_hdr = (struct frag_hdr *) (ip6_hdr + 1);
	fragment_hdr->nexthdr = NEXTHDR_ROUTING;
	routing_hdr = (struct ipv6_rt_hdr *) (fragment_hdr + 1);
	routing_hdr->segments_left = 24;
	success &= assert_true(has_nonzero_segments_left(ip6_hdr, &offset), "Two headers - result");
	success &= assert_equals_u32(40 + 8 + 3, offset, "Two headers - offset");

	// Fall through.
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

static bool test_4to6_translation_simple_udp(void)
{
	return translate(build_ip4_hdr_udp,
			build_l3_payload_udp,
			get_ip6_tuple,
			translating_the_packet_4to6,
			validate_ip6_fixed_hdr_udp_nofrag,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_udp);
}

static bool test_4to6_translation_simple_tcp(void)
{
	return translate(build_ip4_hdr_tcp,
			build_l3_payload_tcp,
			get_ip6_tuple,
			translating_the_packet_4to6,
			validate_ip6_fixed_hdr_tcp_nofrag,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_tcp);
}

static bool test_4to6_translation_simple_icmp(void)
{
	return translate(build_ip4_hdr_icmp4,
			build_l3_payload_icmp4,
			get_ip6_tuple,
			translating_the_packet_4to6,
			validate_ip6_fixed_hdr_icmp_nofrag,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp6_simple);
}

static bool test_4to6_translation_fragment(void)
{
	return translate(build_ip4_hdr_fragment,
			build_l3_payload_udp,
			get_ip6_tuple,
			translating_the_packet_4to6,
			validate_ip6_fixed_hdr_udp_dofrag,
			validate_ip6_frag_hdr_dofrag,
			validate_l3_payload_udp);
}

static bool test_4to6_translation_embedded(void)
{
	return translate(build_ip4_hdr_icmp4_embedded,
			build_l3_payload_icmp4_embedded,
			get_ip6_tuple,
			translating_the_packet_4to6,
			validate_ip6_fixed_hdr_icmp_embedded,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp6_embedded);
}

static bool test_6to4_translation_simple_udp(void)
{
	return translate(build_ip6_hdr_udp,
			build_l3_payload_udp,
			get_ip4_tuple,
			translating_the_packet_6to4,
			validate_ip4_hdr_udp,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_udp);
}

static bool test_6to4_translation_simple_tcp(void)
{
	return translate(build_ip6_hdr_tcp,
			build_l3_payload_tcp,
			get_ip4_tuple,
			translating_the_packet_6to4,
			validate_ip4_hdr_tcp,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_tcp);
}

static bool test_6to4_translation_simple_icmp(void)
{
	return translate(build_ip6_hdr_icmp,
			build_l3_payload_icmp6,
			get_ip4_tuple,
			translating_the_packet_6to4,
			validate_ip4_hdr_icmp4,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp4_simple);
}

static bool test_6to4_translation_fragment(void)
{
	return translate(build_ip6_hdr_fragment,
			build_l3_payload_udp,
			get_ip4_tuple,
			translating_the_packet_6to4,
			validate_ip4_hdr_fragment,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_udp);
}

static bool test_6to4_translation_embedded(void)
{
	return translate(build_ip6_hdr_embedded,
			build_l3_payload_icmp6_embedded,
			get_ip4_tuple,
			translating_the_packet_6to4,
			validate_ip4_hdr_embedded,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp4_embedded);
}

/********************************************
 * Main.
 ********************************************/

int init_module(void)
{
	START_TESTS("Translating the Packet (IPv4 to IPv6)");

	translate_packet_init();

	// 4 to 6 single function tests.
	CALL_TEST(test_function_is_dont_fragment_set(), "Dont fragment getter");
	CALL_TEST(test_function_is_more_fragments_set(), "More fragments getter");
	CALL_TEST(test_function_has_unexpired_src_route(), "Unexpired source route querier");
	CALL_TEST(test_function_build_ipv6_frag_off_field(), "Fragment offset builder");
	CALL_TEST(test_function_build_id_field(), "Identification builder");
	CALL_TEST(test_function_icmp6_minimum_mtu(), "ICMP6 Minimum MTU function");
	CALL_TEST(test_function_icmp4_to_icmp6_param_prob(), "Param problem function");

	// 6 to 4 simple function tests.
	CALL_TEST(test_function_build_tos_field(), "Build TOS function");
	CALL_TEST(test_function_generate_ipv4_id_nofrag(), "Generate id function (no frag)");
	CALL_TEST(test_function_generate_df_flag(), "Generate DF flag function");
	CALL_TEST(test_function_build_ipv4_frag_off_field(), "Generate frag offset + flags function");
	CALL_TEST(test_function_build_protocol_field(), "Build protocol function");
	CALL_TEST(test_function_has_nonzero_segments_left(), "Segments left indicator function");
	CALL_TEST(test_function_generate_ipv4_id_dofrag(), "Generate id function (frag)");
	CALL_TEST(test_function_icmp4_minimum_mtu(), "ICMP4 Minimum MTU function");

	// 4 to 6 full packet translation tests.
	CALL_TEST(test_4to6_translation_simple_udp(), "Simple 4-to-6 UDP translation");
	CALL_TEST(test_4to6_translation_simple_tcp(), "Simple 4-to-6 TCP translation");
	CALL_TEST(test_4to6_translation_simple_icmp(), "Simple 4-to-6 ICMP translation");
	CALL_TEST(test_4to6_translation_fragment(), "4-to-6 translation featuring fragment header");
	CALL_TEST(test_4to6_translation_embedded(), "4-to-6 translation featuring embedded packet");

	// 6 to 4 full packet translation tests.
	CALL_TEST(test_6to4_translation_simple_udp(), "Simple 6-to-4 UDP translation");
	CALL_TEST(test_6to4_translation_simple_tcp(), "Simple 6-to-4 TCP translation");
	CALL_TEST(test_6to4_translation_simple_icmp(), "Simple 6-to-4 ICMP translation");
	CALL_TEST(test_6to4_translation_fragment(), "6-to-4 translation featuring fragment header");
	CALL_TEST(test_6to4_translation_embedded(), "6-to-4 translation featuring embedded packet");

	translate_packet_destroy();

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
