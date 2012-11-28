#include <linux/module.h>
#include <linux/printk.h>

#include "unit_test.h"
#include "nf_nat64_translate_packet.c"

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

static struct nf_conntrack_tuple get_ip4_tuple(void)
{
	struct nf_conntrack_tuple result;

	result.ipv4_src_addr.s_addr = cpu_to_be32(0x57613990);
	result.ipv4_dst_addr.s_addr = cpu_to_be32(0x97254347);

	return result;
}

static struct nf_conntrack_tuple get_ip6_tuple(void)
{
	struct nf_conntrack_tuple result;

	result.ipv6_src_addr.s6_addr32[0] = cpu_to_be32(0x01234567);
	result.ipv6_src_addr.s6_addr32[1] = cpu_to_be32(0x89ABCDEF);
	result.ipv6_src_addr.s6_addr32[2] = cpu_to_be32(0x12345678);
	result.ipv6_src_addr.s6_addr32[3] = cpu_to_be32(0x9ABCDEF0);

	result.ipv6_dst_addr.s6_addr32[0] = cpu_to_be32(0x76543210);
	result.ipv6_dst_addr.s6_addr32[1] = cpu_to_be32(0xFEDCBA98);
	result.ipv6_dst_addr.s6_addr32[2] = cpu_to_be32(0x87654321);
	result.ipv6_dst_addr.s6_addr32[3] = cpu_to_be32(0x0FEDCBA9);

	return result;
}

static bool build_ip4_hdr_udp(void **l3_header, __u16 *l3_hdr_len)
{
	struct iphdr *ip_header = kmalloc(sizeof(struct iphdr), GFP_ATOMIC);
	if (!ip_header)
		return false;

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
	if (!hdr)
		return false;

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

	// TODO (test) no estás printkeando error cuando no se puede reservar memoria.
	fixed_hdr = kmalloc(sizeof(*fixed_hdr) + sizeof(*frag_hdr), GFP_ATOMIC);
	if (!fixed_hdr)
		goto failure;
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
	if (!udp_header)
		return false;

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
	if (!tcp_header)
		return false;

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
	if (!icmp4_header)
		return false;

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
	if (!icmp6_header)
		return false;

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
	if (!(*l3_payload))
		return false;

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

	udp_header->source = cpu_to_be16(5883);
	udp_header->dest = cpu_to_be16(9215);
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
	if (!(*l3_payload))
		return false;

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

	udp_header->source = cpu_to_be16(5883);
	udp_header->dest = cpu_to_be16(9215);
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
		printk(KERN_WARNING "Could not allocate a test packet.");
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
		struct nf_conntrack_tuple (*tuple_function)(void),
		bool (*fixed_hdr_validate_function)(void *),
		bool (*frag_hdr_validate_function)(struct frag_hdr *),
		bool (*l4_validate_function)(void *l4_hdr))
{
	// Init.
	struct sk_buff *packet_in = build_test_skb(l3_hdr_function, l3_payload_function);
	struct sk_buff *packet_out = NULL;
	struct nf_conntrack_tuple tuple_in = tuple_function();

	if (!packet_in)
		goto error;

	// Execute.
	if (!nat64_translating_the_packet(&tuple_in, packet_in, &packet_out))
		goto error;

	// Validate.
	if (packet_out == NULL) {
		printk(KERN_WARNING "nat64_translating_the_packet() returned success "
				"but the resulting packet is NULL.");
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
	struct nf_conntrack_tuple dummy_tuple = get_ip6_tuple();

	ASSERT_EQUALS(6, hdr->version, "Version");
	ASSERT_EQUALS(0, hdr->priority, "Traffic class");
	ASSERT_EQUALS(0, hdr->flow_lbl[0], "Flow label (0)");
	ASSERT_EQUALS(0, hdr->flow_lbl[1], "Flow label (1)");
	ASSERT_EQUALS(0, hdr->flow_lbl[2], "Flow label (2)");
	// ASSERT_EQUALS(, be16_to_cpu(hdr->payload_len), "Payload len");
	// ASSERT_EQUALS(, hdr->nexthdr, "Next header");
	// ASSERT_EQUALS(5, hdr->hop_limit, "Hop limit");
	ASSERT_EQUALS(0, memcmp(&dummy_tuple.ipv6_src_addr, &hdr->saddr, sizeof(hdr->saddr)),
			"Source address");
	ASSERT_EQUALS(0, memcmp(&dummy_tuple.ipv6_dst_addr, &hdr->daddr, sizeof(hdr->saddr)),
			"Dest address");

	return true;
}

static bool validate_ip6_fixed_hdr_udp_nofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;

	if (!validate_ip6_fixed_hdr_common(ip6_header))
		return false;

	// udp hdr + payload.
	ASSERT_EQUALS(8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	ASSERT_EQUALS(IPPROTO_UDP, hdr->nexthdr, "Next header");
	ASSERT_EQUALS(5, hdr->hop_limit, "Hop limit");

	return true;
}

static bool validate_ip6_fixed_hdr_tcp_nofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;

	if (!validate_ip6_fixed_hdr_common(ip6_header))
		return false;

	// tcp hdr + payload.
	ASSERT_EQUALS(20 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	ASSERT_EQUALS(IPPROTO_TCP, hdr->nexthdr, "Next header");
	ASSERT_EQUALS(5, hdr->hop_limit, "Hop limit");

	return true;
}

static bool validate_ip6_fixed_hdr_icmp_nofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;

	if (!validate_ip6_fixed_hdr_common(ip6_header))
		return false;

	// icmpv6 hdr + payload.
	ASSERT_EQUALS(8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	ASSERT_EQUALS(NEXTHDR_ICMP, hdr->nexthdr, "Next header");
	ASSERT_EQUALS(5, hdr->hop_limit, "Hop limit");

	return true;
}

static bool validate_ip6_fixed_hdr_icmp_embedded(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;

	if (!validate_ip6_fixed_hdr_common(ip6_header))
		return false;

	// icmp hdr + ipv6 hdr + udp hdr + payload.
	ASSERT_EQUALS(8 + 40 + 8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	ASSERT_EQUALS(NEXTHDR_ICMP, hdr->nexthdr, "Next header");
	ASSERT_EQUALS(5, hdr->hop_limit, "Hop limit");

	return true;
}

static bool validate_ip6_fixed_hdr_udp_dofrag(void *ip6_header)
{
	struct ipv6hdr *hdr = ip6_header;

	if (!validate_ip6_fixed_hdr_common(ip6_header))
		return false;

	// frag hdr + udp hdr + payload.
	ASSERT_EQUALS(8 + 8 + 4, be16_to_cpu(hdr->payload_len), "Payload len");
	ASSERT_EQUALS(NEXTHDR_FRAGMENT, hdr->nexthdr, "Next header");
	ASSERT_EQUALS(5, hdr->hop_limit, "Hop limit");

	return true;
}

static bool validate_ip6_frag_hdr_nofrag(struct frag_hdr *frag_header)
{
	return true;
}

static bool validate_ip6_frag_hdr_dofrag(struct frag_hdr *frag_header)
{
	ASSERT_EQUALS(IPPROTO_UDP, frag_header->nexthdr, "Frag hdr's next header");
	ASSERT_EQUALS(0, frag_header->reserved, "Frag hdr's reserved");
	ASSERT_EQUALS(0x0675 << 3, be16_to_cpu(frag_header->frag_off), "Frag hdr's fragment offset");
	ASSERT_EQUALS(1234, be32_to_cpu(frag_header->identification), "Frag hdr's identification");

	return true;
}

static bool validate_ip4_hdr_common(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	struct nf_conntrack_tuple dummy_tuple = get_ip4_tuple();

	ASSERT_EQUALS(4, hdr->version, "Version");
	ASSERT_EQUALS(5, hdr->ihl, "Internet Header Length");
	ASSERT_EQUALS(0xA7, hdr->tos, "Type of Service");
	// ASSERT_EQUALS(, be16_to_cpu(hdr->tot_len), "Total Length");
	ASSERT_EQUALS(0, be16_to_cpu(hdr->id), "Identification");
	ASSERT_EQUALS(IP_DF, be16_to_cpu(hdr->frag_off), "Flags & Fragment Offset");
	ASSERT_EQUALS(5, hdr->ttl, "Time to Live");
	// ASSERT_EQUALS(, hdr->protocol, "Protocol");
	// ASSERT_EQUALS(, hdr->check, "Header Checksum");
	ASSERT_EQUALS(dummy_tuple.ipv4_src_addr.s_addr, hdr->saddr, "Source address");
	ASSERT_EQUALS(dummy_tuple.ipv4_dst_addr.s_addr, hdr->daddr, "Dest address");

	return true;
}

static bool validate_ip4_hdr_udp(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;

	if (!validate_ip4_hdr_common(l3_hdr))
		return false;

	// iphdr + udphdr + 4
	ASSERT_EQUALS(20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	ASSERT_EQUALS(IPPROTO_UDP, hdr->protocol, "Protocol");

	return true;
}

static bool validate_ip4_hdr_tcp(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;

	if (!validate_ip4_hdr_common(l3_hdr))
		return false;

	// iphdr + tcphdr + 4
	ASSERT_EQUALS(20 + 20 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	ASSERT_EQUALS(IPPROTO_TCP, hdr->protocol, "Protocol");

	return true;
}

static bool validate_ip4_hdr_icmp4(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;

	if (!validate_ip4_hdr_common(l3_hdr))
		return false;

	// iphdr + icmphdr + 4
	ASSERT_EQUALS(20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	ASSERT_EQUALS(IPPROTO_ICMP, hdr->protocol, "Protocol");

	return true;
}

static bool validate_ip4_hdr_fragment(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;
	struct nf_conntrack_tuple dummy_tuple = get_ip4_tuple();

	ASSERT_EQUALS(4, hdr->version, "Version");
	ASSERT_EQUALS(5, hdr->ihl, "Internet Header Length");
	ASSERT_EQUALS(0xA7, hdr->tos, "Type of Service");
	// iphdr + udphdr + payload.
	ASSERT_EQUALS(20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	ASSERT_EQUALS(385, be16_to_cpu(hdr->id), "Identification"); //
	ASSERT_EQUALS(16, be16_to_cpu(hdr->frag_off), "Flags & Fragment Offset"); //
	ASSERT_EQUALS(5, hdr->ttl, "Time to Live");
	ASSERT_EQUALS(IPPROTO_UDP, hdr->protocol, "Protocol"); //
	// ASSERT_EQUALS(, hdr->check, "Header Checksum");
	ASSERT_EQUALS(dummy_tuple.ipv4_src_addr.s_addr, hdr->saddr, "Source address");
	ASSERT_EQUALS(dummy_tuple.ipv4_dst_addr.s_addr, hdr->daddr, "Dest address");

	return true;
}

static bool validate_ip4_hdr_embedded(void *l3_hdr)
{
	struct iphdr *hdr = l3_hdr;

	if (!validate_ip4_hdr_common(l3_hdr))
		return false;

	// iphdr + icmphdr + iphdr + udphdr + 4
	ASSERT_EQUALS(20 + 8 + 20 + 8 + 4, be16_to_cpu(hdr->tot_len), "Total Length");
	ASSERT_EQUALS(IPPROTO_ICMP, hdr->protocol, "Protocol");

	return true;
}

static bool validate_simple_payload(unsigned char *payload)
{
	ASSERT_EQUALS(0x54, payload[0], "Payload, first chara.");
	ASSERT_EQUALS(0x45, payload[1], "Payload, second chara.");
	ASSERT_EQUALS(0x53, payload[2], "Payload, third chara.");
	ASSERT_EQUALS(0x54, payload[3], "Payload, fourth chara.");

	return true;
}

static bool validate_l3_payload_udp(void *l4_hdr)
{
	struct udphdr *udp_header = l4_hdr;

	ASSERT_EQUALS(5883, be16_to_cpu(udp_header->source), "UDP source port");
	ASSERT_EQUALS(9215, be16_to_cpu(udp_header->dest), "UDP dest port");
	ASSERT_EQUALS(8 + 4, be16_to_cpu(udp_header->len), "UDP length");
	// ASSERT_EQUALS(0xAFAF, be16_to_cpu(udp_header->check), "UDP checksum");

	if (!validate_simple_payload((unsigned char *) (udp_header + 1)))
		return false;

	return true;
}

static bool validate_l3_payload_tcp(void *l4_hdr)
{
	struct tcphdr *tcp_header = l4_hdr;

	ASSERT_EQUALS(3885, be16_to_cpu(tcp_header->source), "Source port");
	ASSERT_EQUALS(1592, be16_to_cpu(tcp_header->dest), "Dest port");
	ASSERT_EQUALS(112233, be32_to_cpu(tcp_header->seq), "Seq number");
	ASSERT_EQUALS(332211, be32_to_cpu(tcp_header->ack_seq), "ACK number");
	ASSERT_EQUALS(5, tcp_header->doff, "Data offset");
	ASSERT_EQUALS(0, tcp_header->res1, "Reserved & NS");
	ASSERT_EQUALS(0, tcp_header->cwr, "CWR");
	ASSERT_EQUALS(0, tcp_header->ece, "ECE");
	ASSERT_EQUALS(0, tcp_header->urg, "URG");
	ASSERT_EQUALS(1, tcp_header->ack, "ACK");
	ASSERT_EQUALS(0, tcp_header->psh, "PSH");
	ASSERT_EQUALS(0, tcp_header->rst, "RST");
	ASSERT_EQUALS(0, tcp_header->syn, "SYN");
	ASSERT_EQUALS(0, tcp_header->fin, "FIN");
	ASSERT_EQUALS(300, be16_to_cpu(tcp_header->window), "Window size");
	// ASSERT_EQUALS(, tcp_header->check, "Checksum");
	ASSERT_EQUALS(0, be16_to_cpu(tcp_header->urg_ptr), "Urgent pointer");

	return true;
}

static bool validate_l3_payload_icmp4_simple(void *l4_hdr)
{
	struct icmphdr *icmp4_header = l4_hdr;

	ASSERT_EQUALS(ICMP_ECHOREPLY, icmp4_header->type, "Type");
	ASSERT_EQUALS(0, icmp4_header->code, "Code");
	// ASSERT_EQUALS(, icmp4_header->checksum, "Checksum");
	ASSERT_EQUALS(45, be16_to_cpu(icmp4_header->un.echo.id), "Echo ID");
	ASSERT_EQUALS(54, be16_to_cpu(icmp4_header->un.echo.sequence), "Echo seq");

	return true;
}

static bool validate_l3_payload_icmp4_embedded(void *l4_hdr)
{
	struct icmphdr *icmp4_header = l4_hdr;
	struct iphdr *ip4_header = (struct iphdr *) (icmp4_header + 1);
	struct udphdr *udp_header = (struct udphdr *) (ip4_header + 1);

	ASSERT_EQUALS(ICMP_TIME_EXCEEDED, icmp4_header->type, "ICMP Type");
	ASSERT_EQUALS(0, icmp4_header->code, "ICMP Code");
	// ASSERT_EQUALS(, icmp4_header->checksum, "ICMP Checksum");
	ASSERT_EQUALS(0, be32_to_cpu(icmp4_header->un.gateway), "ICMP Unused");

	if (!validate_ip4_hdr_common(ip4_header))
		return false;
	// That the code writes garbage in both the inner tot_len and the checksum is a known quirk.
	// The inner packet is usually minced so nobody should trust those fields.
	// ASSERT_EQUALS(iphdr + udphdr + 4, be16_to_cpu(ip4_header->tot_len), "Inner total Length");
	ASSERT_EQUALS(IPPROTO_UDP, ip4_header->protocol, "Inner protocol");
	// ASSERT_EQUALS(iphdr + udphdr + 4, be16_to_cpu(ip4_header->tot_len), "Inner checksum");

	if (!validate_l3_payload_udp(udp_header))
		return false;

	return true;
}

static bool validate_l3_payload_icmp6_simple(void *l4_hdr)
{
	struct icmp6hdr *hdr = l4_hdr;

	ASSERT_EQUALS(ICMPV6_ECHO_REPLY, hdr->icmp6_type, "ICMP type");
	ASSERT_EQUALS(0, hdr->icmp6_code, "ICMP code");
	// ASSERT_EQUALS(6, hdr->icmp6_cksum, "ICMP checksum");
	ASSERT_EQUALS(45, be16_to_cpu(hdr->icmp6_dataun.u_echo.identifier), "ICMP echo reply id");
	ASSERT_EQUALS(54, be16_to_cpu(hdr->icmp6_dataun.u_echo.sequence), "ICMP echo reply seq");

	return true;
}

static bool validate_l3_payload_icmp6_embedded(void *l4_hdr)
{
	struct icmp6hdr *icmp6_header = l4_hdr;
	struct ipv6hdr *ip6_header = (struct ipv6hdr *) (icmp6_header + 1);
	struct udphdr *udp_header = (struct udphdr *) (ip6_header + 1);

	ASSERT_EQUALS(ICMPV6_TIME_EXCEED, icmp6_header->icmp6_type, "ICMP type");
	ASSERT_EQUALS(0, icmp6_header->icmp6_code, "ICMP code");
	// ASSERT_EQUALS(6, icmp6_header->icmp6_cksum, "ICMP checksum");
	ASSERT_EQUALS(0, be32_to_cpu(icmp6_header->icmp6_unused), "ICMP unused");

	if (!validate_ip6_fixed_hdr_common(ip6_header))
		return false;
	// That the code writes garbage in both the inner payload_len and the checksum is a known quirk.
	// The inner packet is usually minced so nobody should trust those fields.
	// ASSERT_EQUALS(udp hdr + payload, be16_to_cpu(ip6_header->payload_len), "Inner payload len");
	ASSERT_EQUALS(IPPROTO_UDP, ip6_header->nexthdr, "Inner next header");
	ASSERT_EQUALS(0, ip6_header->hop_limit, "Inner hop limit");

	if (!validate_l3_payload_udp(udp_header))
		return false;

	return true;
}

/********************************************
 * Tests.
 ********************************************/

static bool test_function_is_dont_fragment_set(void)
{
	struct iphdr hdr;

	hdr.frag_off = cpu_to_be16(0x0000);
	ASSERT_EQUALS(0, is_dont_fragment_set(&hdr), "All zeroes.");

	hdr.frag_off = cpu_to_be16(0x4000);
	ASSERT_EQUALS(1, is_dont_fragment_set(&hdr), "All zeroes except DF.");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	ASSERT_EQUALS(1, is_dont_fragment_set(&hdr), "All ones.");

	hdr.frag_off = cpu_to_be16(0xBFFF);
	ASSERT_EQUALS(0, is_dont_fragment_set(&hdr), "All ones except DF.");

	return true;
}

static bool test_function_is_more_fragments_set(void)
{
	struct iphdr hdr;

	hdr.frag_off = cpu_to_be16(0x0000);
	ASSERT_EQUALS(0, is_more_fragments_set(&hdr), "All zeroes.");

	hdr.frag_off = cpu_to_be16(0x2000);
	ASSERT_EQUALS(1, is_more_fragments_set(&hdr), "All zeroes except MF.");

	hdr.frag_off = cpu_to_be16(0xFFFF);
	ASSERT_EQUALS(1, is_more_fragments_set(&hdr), "All ones.");

	hdr.frag_off = cpu_to_be16(0xDFFF);
	ASSERT_EQUALS(0, is_more_fragments_set(&hdr), "All ones except MF.");

	return true;
}

static bool test_function_has_unexpired_src_route(void)
{
	struct iphdr *hdr = kmalloc(60, GFP_ATOMIC); // 60 is the max value allowed by hdr.ihl.
	unsigned char *options;
	if (!hdr) {
		printk(KERN_WARNING "Can't allocate a test header.");
		goto failure;
	}
	options = (unsigned char *) (hdr + 1);

	hdr->ihl = 5; // min legal value.
	ASSERT_EQUALS(false, has_unexpired_src_route(hdr), "No options");

	hdr->ihl = 6;
	options[0] = IPOPT_SID;
	options[1] = 4;
	options[2] = 0xAB;
	options[3] = 0xCD;
	ASSERT_EQUALS(false, has_unexpired_src_route(hdr), "No source route option, simple.");

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
	ASSERT_EQUALS(false, has_unexpired_src_route(hdr), "No source option, multiple options.");

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
	ASSERT_EQUALS(false, has_unexpired_src_route(hdr), "Expired source route.");

	options[2] = 4;
	ASSERT_EQUALS(true, has_unexpired_src_route(hdr), "Unexpired source route, first address.");
	options[2] = 8;
	ASSERT_EQUALS(true, has_unexpired_src_route(hdr), "Unexpired source route, second address.");
	options[2] = 12;
	ASSERT_EQUALS(true, has_unexpired_src_route(hdr), "Unexpired source route, third address.");

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
	ASSERT_EQUALS(false, has_unexpired_src_route(hdr), "Expired source route, multiple options.");

	options[7] = 4;
	ASSERT_EQUALS(true, has_unexpired_src_route(hdr), "Unexpired src route, multiple options (1).");
	options[7] = 8;
	ASSERT_EQUALS(true, has_unexpired_src_route(hdr), "Unexpired src route, multiple options (2).");
	options[7] = 12;
	ASSERT_EQUALS(true, has_unexpired_src_route(hdr), "Unexpired src route, multiple options (3).");

	kfree(hdr);
	return true;

failure:
	kfree(hdr);
	return false;
}

static bool test_function_build_ipv6_frag_off_field(void)
{
	struct iphdr hdr;

	// 0x32E9 = 001 1001011101001
	hdr.frag_off = cpu_to_be16(0x32E9);
	// 0x9749 = 1001011101001 001
	ASSERT_EQUALS(cpu_to_be16(0x9749), build_ipv6_frag_off_field(&hdr), "More fragments on.");

	// 0xD15A = 110 1000101011010
	hdr.frag_off = cpu_to_be16(0xD15A);
	// 0x8AD0 = 1000101011010 000
	ASSERT_EQUALS(cpu_to_be16(0x8AD0), build_ipv6_frag_off_field(&hdr), "More fragments off.");

	return true;
}

static bool test_function_build_id_field(void)
{
	struct iphdr hdr;

	hdr.id = cpu_to_be16(1234);
	ASSERT_EQUALS(cpu_to_be32(1234), build_id_field(&hdr), "Simple.");

	return true;
}

#define min_mtu(packet, in, out, len) be16_to_cpu(icmp6_minimum_mtu(packet, in, out, len))
static bool test_function_icmp6_minimum_mtu(void)
{
	int i;

	// Test the bare minimum functionality.
	ASSERT_EQUALS(1, min_mtu(1, 2, 2, 0), "No hacks, min is packet.");
	ASSERT_EQUALS(1, min_mtu(2, 1, 2, 0), "No hacks, min is in.");
	ASSERT_EQUALS(1, min_mtu(2, 2, 1, 0), "No hacks, min is out.");

	// Test hack 1: MTU is overriden if some router set is as zero.
	for (i = 1500; i > 1400; --i)
		ASSERT_EQUALS(1400, min_mtu(0, 1600, 1600, i), "Override packet MTU.");
	for (i = 1400; i > 1200; --i)
		ASSERT_EQUALS(1200, min_mtu(0, 1600, 1600, i), "Override packet MTU.");
	for (i = 1200; i > 600; --i)
		ASSERT_EQUALS(600, min_mtu(0, 1600, 1600, i), "Override packet MTU.");
	for (i = 600; i > 0; --i)
		ASSERT_EQUALS(0, min_mtu(0, 1600, 1600, i), "Override packet MTU.");

	ASSERT_EQUALS(1, min_mtu(0, 1, 2, 1000), "Override packet MTU, min is in.");
	ASSERT_EQUALS(1, min_mtu(0, 2, 1, 1000), "Override packet MTU, min is out.");

	// Test hack 2: User wants us to try to improve the failure rate.
	config.improve_mtu_failure_rate = true;

	ASSERT_EQUALS(1280, min_mtu(1, 2, 2, 0), "Improve rate, min is packet.");
	ASSERT_EQUALS(1280, min_mtu(2, 1, 2, 0), "Improve rate, min is in.");
	ASSERT_EQUALS(1280, min_mtu(2, 2, 1, 0), "Improve rate, min is out.");

	ASSERT_EQUALS(1300, min_mtu(1300, 1400, 1400, 0), "Improve rate (not), min is packet.");
	ASSERT_EQUALS(1300, min_mtu(1400, 1300, 1400, 0), "Improve rate (not), min is in.");
	ASSERT_EQUALS(1300, min_mtu(1400, 1400, 1300, 0), "Improve rate (not), min is out.");

	// Test both hacks at the same time.
	ASSERT_EQUALS(1280, min_mtu(0, 700, 700, 1000), "2 hacks, min is packet/overriden.");
	ASSERT_EQUALS(1280, min_mtu(0, 1, 2, 1000), "2 hacks, min is in/overriden.");
	ASSERT_EQUALS(1280, min_mtu(0, 2, 1, 1000), "2 hacks, min is out/overriden.");

	ASSERT_EQUALS(1400, min_mtu(0, 1500, 1500, 1401), "2 hacks, min is packet/not 1280.");
	ASSERT_EQUALS(1400, min_mtu(0, 1400, 1500, 1501), "2 hacks, min is in/not 1280.");
	ASSERT_EQUALS(1400, min_mtu(0, 1500, 1400, 1501), "2 hacks, min is out/not 1280.");

	// Revert the config, just in case.
	config.improve_mtu_failure_rate = false;

	return true;
}
#undef min_mtu

static bool test_4to6_translation_simple_udp(void)
{
	return translate(build_ip4_hdr_udp,
			build_l3_payload_udp,
			get_ip6_tuple,
			validate_ip6_fixed_hdr_udp_nofrag,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_udp);
}

static bool test_4to6_translation_simple_tcp(void)
{
	return translate(build_ip4_hdr_tcp,
			build_l3_payload_tcp,
			get_ip6_tuple,
			validate_ip6_fixed_hdr_tcp_nofrag,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_tcp);
}

static bool test_4to6_translation_simple_icmp(void)
{
	return translate(build_ip4_hdr_icmp4,
			build_l3_payload_icmp4,
			get_ip6_tuple,
			validate_ip6_fixed_hdr_icmp_nofrag,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp6_simple);
}

static bool test_4to6_translation_fragment(void)
{
	return translate(build_ip4_hdr_fragment,
			build_l3_payload_udp,
			get_ip6_tuple,
			validate_ip6_fixed_hdr_udp_dofrag,
			validate_ip6_frag_hdr_dofrag,
			validate_l3_payload_udp);
}

static bool test_4to6_translation_embedded(void)
{
	return translate(build_ip4_hdr_icmp4_embedded,
			build_l3_payload_icmp4_embedded,
			get_ip6_tuple,
			validate_ip6_fixed_hdr_icmp_embedded,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp6_embedded);
}

static bool test_6to4_translation_simple_udp(void)
{
	return translate(build_ip6_hdr_udp,
			build_l3_payload_udp,
			get_ip4_tuple,
			validate_ip4_hdr_udp,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_udp);
}

static bool test_6to4_translation_simple_tcp(void)
{
	return translate(build_ip6_hdr_tcp,
			build_l3_payload_tcp,
			get_ip4_tuple,
			validate_ip4_hdr_tcp,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_tcp);
}

static bool test_6to4_translation_simple_icmp(void)
{
	return translate(build_ip6_hdr_icmp,
			build_l3_payload_icmp6,
			get_ip4_tuple,
			validate_ip4_hdr_icmp4,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp4_simple);
}

static bool test_6to4_translation_fragment(void)
{
	return translate(build_ip6_hdr_fragment,
			build_l3_payload_udp,
			get_ip4_tuple,
			validate_ip4_hdr_fragment,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_udp);
}

static bool test_6to4_translation_embedded(void)
{
	return translate(build_ip6_hdr_embedded,
			build_l3_payload_icmp6_embedded,
			get_ip4_tuple,
			validate_ip4_hdr_embedded,
			validate_ip6_frag_hdr_nofrag,
			validate_l3_payload_icmp4_embedded);
}

/********************************************
 * Main.
 ********************************************/

int init_module(void)
{
	__u16 plateaus[] = { 1400, 1200, 600 };
	START_TESTS("Translating the Packet (IPv4 to IPv6)");

	config.packet_head_room = 5;
	config.packet_tail_room = 5;
	config.override_ipv6_traffic_class = true;
	config.override_ipv4_traffic_class = false;
	config.ipv4_traffic_class = 5;
	config.df_always_set = true;
	config.generate_ipv4_id = false;
	config.improve_mtu_failure_rate = false;
	config.ipv6_nexthop_mtu = 1300;
	config.ipv4_nexthop_mtu = 1400;
	config.mtu_plateaus = plateaus;
	config.mtu_plateau_count = 3;

	CALL_TEST(test_function_is_dont_fragment_set(), "Dont fragment getter");
	CALL_TEST(test_function_is_more_fragments_set(), "More fragments getter");
	CALL_TEST(test_function_has_unexpired_src_route(), "Unexpired source route querier");
	CALL_TEST(test_function_build_ipv6_frag_off_field(), "Fragment offset builder");
	CALL_TEST(test_function_build_id_field(), "Identification builder");
	CALL_TEST(test_function_icmp6_minimum_mtu(), "Minimum MTU function");

	CALL_TEST(test_4to6_translation_simple_udp(), "Simple 4-to-6 UDP translation");
	CALL_TEST(test_4to6_translation_simple_tcp(), "Simple 4-to-6 TCP translation");
	CALL_TEST(test_4to6_translation_simple_icmp(), "Simple 4-to-6 ICMP translation");
	CALL_TEST(test_4to6_translation_fragment(), "4-to-6 translation featuring fragment header");
	CALL_TEST(test_4to6_translation_embedded(), "4-to-6 translation featuring embedded packet");

	CALL_TEST(test_6to4_translation_simple_udp(), "Simple 6-to-4 UDP translation");
	CALL_TEST(test_6to4_translation_simple_tcp(), "Simple 6-to-4 TCP translation");
	CALL_TEST(test_6to4_translation_simple_icmp(), "Simple 6-to-4 ICMP translation");
	CALL_TEST(test_6to4_translation_fragment(), "6-to-4 translation featuring fragment header");
	CALL_TEST(test_6to4_translation_embedded(), "6-to-4 translation featuring embedded packet");

	END_TESTS;
}

void cleanup_module(void)
{
	// No code.
}
