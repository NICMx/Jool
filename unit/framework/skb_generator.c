#include "nat64/unit/skb_generator.h"
#include "nat64/unit/types.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/packet_db.h"

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>


#define IPV4_HDR_LEN sizeof(struct iphdr)
int init_ipv4_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, void *arg)
{
	struct iphdr *hdr = l3_hdr;
	struct ipv4_pair *pair4 = arg;

	hdr->version = 4;
	hdr->ihl = 5;
	hdr->tos = 0;
	hdr->tot_len = cpu_to_be16(sizeof(*hdr) + payload_len);
	hdr->id = cpu_to_be16(1234);
	hdr->frag_off = build_ipv4_frag_off_field(true, false, 0);
	hdr->ttl = 32;
	hdr->protocol = nexthdr;
	hdr->saddr = pair4->remote.address.s_addr;
	hdr->daddr = pair4->local.address.s_addr;

	hdr->check = 0;
	hdr->check = ip_fast_csum(hdr, hdr->ihl);

	return 0;
}

#define IPV6_HDR_LEN sizeof(struct ipv6hdr)
int init_ipv6_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, void *arg)
{
	struct ipv6hdr *hdr = l3_hdr;
	struct ipv6_pair *pair6 = arg;

	hdr->version = 6;
	hdr->priority = 0;
	hdr->flow_lbl[0] = 0;
	hdr->flow_lbl[1] = 0;
	hdr->flow_lbl[2] = 0;
	hdr->payload_len = cpu_to_be16(payload_len);
	hdr->nexthdr = nexthdr;
	hdr->hop_limit = 32;
	hdr->saddr = pair6->remote.address;
	hdr->daddr = pair6->local.address;

	return 0;
}

#define FRAG_HDR_LEN sizeof(struct frag_hdr)
static int init_ipv6_and_frag_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, void *arg)
{
	struct ipv6hdr *hdr6 = l3_hdr;
	struct frag_hdr *frag_hdr = (struct frag_hdr *) (hdr6 + 1);
	int error;

	error = init_ipv6_hdr(hdr6, FRAG_HDR_LEN + payload_len, NEXTHDR_FRAGMENT, arg);
	if (error != 0)
		return error;

	frag_hdr->nexthdr = nexthdr;
	frag_hdr->reserved = 0;
	frag_hdr->frag_off = cpu_to_be16(0);
	frag_hdr->identification = cpu_to_be32(4321);

	return 0;
}

#define UDP_HDR_LEN sizeof(struct udphdr)
static int init_udp_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg)
{
	struct udphdr *hdr = l4_hdr;
	struct ipv6_pair *pair6;
	struct ipv4_pair *pair4;

	switch (l3_hdr_type) {
	case ETH_P_IPV6:
		pair6 = arg;
		hdr->source = cpu_to_be16(pair6->remote.l4_id);
		hdr->dest = cpu_to_be16(pair6->local.l4_id);
		break;
	case ETH_P_IP:
		pair4 = arg;
		hdr->source = cpu_to_be16(pair4->remote.l4_id);
		hdr->dest = cpu_to_be16(pair4->local.l4_id);
		break;
	default:
		log_warning("Unsupported network protocol: %d.", l3_hdr_type);
		return -EINVAL;
	}

	hdr->len = cpu_to_be16(datagram_len);
	hdr->check = 0;

	return 0;
}

#define TCP_HDR_LEN sizeof(struct tcphdr)
int init_tcp_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg)
{
	struct tcphdr *hdr = l4_hdr;
	struct ipv6_pair *pair6;
	struct ipv4_pair *pair4;

	switch (l3_hdr_type) {
	case ETH_P_IPV6:
		pair6 = arg;
		hdr->source = cpu_to_be16(pair6->remote.l4_id);
		hdr->dest = cpu_to_be16(pair6->local.l4_id);
		break;
	case ETH_P_IP:
		pair4 = arg;
		hdr->source = cpu_to_be16(pair4->remote.l4_id);
		hdr->dest = cpu_to_be16(pair4->local.l4_id);
		break;
	default:
		log_warning("Unsupported network protocol: %d.", l3_hdr_type);
		return -EINVAL;
	}

	hdr->seq = cpu_to_be32(4669);
	hdr->ack_seq = cpu_to_be32(6576);
	hdr->doff = sizeof(*hdr) / 4;
	hdr->res1 = 0;
	hdr->cwr = 0;
	hdr->ece = 0;
	hdr->urg = 0;
	hdr->ack = 0;
	hdr->psh = 0;
	hdr->rst = 0;
	hdr->syn = 0;
	hdr->fin = 0;
	hdr->window = cpu_to_be16(3233);
	hdr->check = 0;
	hdr->urg_ptr = cpu_to_be16(9865);

	return 0;
}

#define ICMP4_HDR_LEN sizeof(struct icmphdr)
static int init_icmp4_hdr_info(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg)
{
	struct icmphdr *hdr = l4_hdr;
	struct ipv4_pair *pair4 = arg;

	hdr->type = ICMP_ECHO;
	hdr->code = 0;
	hdr->checksum = 0;
	hdr->un.echo.id = cpu_to_be16(pair4->remote.l4_id);
	hdr->un.echo.sequence = cpu_to_be16(2000);

	return 0;
}

static int init_icmp4_hdr_error(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg)
{
	struct icmphdr *hdr = l4_hdr;

	hdr->type = ICMP_DEST_UNREACH;
	hdr->code = ICMP_FRAG_NEEDED;
	hdr->checksum = 0;
	hdr->un.frag.mtu = cpu_to_be16(1300);
	hdr->un.frag.__unused = cpu_to_be16(0);

	return 0;
}

#define ICMP6_HDR_LEN sizeof(struct icmp6hdr)
static int init_icmp6_hdr_info(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg)
{
	struct icmp6hdr *hdr = l4_hdr;
	struct ipv6_pair *pair6 = arg;

	hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
	hdr->icmp6_code = 0;
	hdr->icmp6_cksum = 0;
	hdr->icmp6_dataun.u_echo.identifier = cpu_to_be16(pair6->remote.l4_id);
	hdr->icmp6_dataun.u_echo.sequence = cpu_to_be16(4000);

	return 0;
}

static int init_icmp6_hdr_error(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg)
{
	struct icmp6hdr *hdr = l4_hdr;

	hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
	hdr->icmp6_code = 0;
	hdr->icmp6_cksum = 0;
	hdr->icmp6_mtu = cpu_to_be32(3100);

	return 0;
}

static int init_empty_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg)
{
	return 0;
}

int init_payload_normal(void *target, u16 payload_len)
{
	unsigned char *payload = target;
	u16 i;

	for (i = 0; i < payload_len; i++)
		payload[i] = i;

	return 0;
}

static int init_payload_inner_ipv6(void *target, u16 payload_len)
{
	struct ipv6hdr *hdr_ipv6;
	struct tcphdr *hdr_tcp;
	unsigned char *inner_payload;
	struct ipv6_pair pair6;
	int error;

	error = init_pair6(&pair6, "5::5", 55, "6::6", 66);
	if (error)
		return error;

	hdr_ipv6 = target;
	hdr_tcp = (struct tcphdr *) (hdr_ipv6 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	error = init_ipv6_hdr(hdr_ipv6, 1300, NEXTHDR_TCP, &pair6);
	if (error)
		return error;
	error = init_tcp_hdr(hdr_tcp, ETH_P_IPV6, 1300, &pair6);
	if (error)
		return error;
	error = init_payload_normal(inner_payload, payload_len - sizeof(*hdr_ipv6) - sizeof(*hdr_tcp));
	if (error)
		return error;

	return 0;
}

static int init_payload_inner_ipv4(void *target, u16 payload_len)
{
	struct iphdr *hdr_ipv4;
	struct tcphdr *hdr_tcp;
	unsigned char *inner_payload;
	struct ipv4_pair pair4;
	int error;

	error = init_pair4(&pair4, "5.5.5.5", 555, "6.6.6.6", 666);
	if (error)
		return error;

	hdr_ipv4 = target;
	hdr_tcp = (struct tcphdr *) (hdr_ipv4 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	error = init_ipv4_hdr(hdr_ipv4, 1300, IPPROTO_TCP, &pair4);
	if (error)
		return error;
	error = init_tcp_hdr(hdr_tcp, ETH_P_IP, 1300, &pair4);
	if (error)
		return error;

	error = init_payload_normal(inner_payload, payload_len - sizeof(*hdr_ipv4) - sizeof(*hdr_tcp));
	if (error)
		return error;

	return 0;
}

static int empty_post(void *l4_hdr, u16 datagram_len, void *arg)
{
	return 0;
}

int ipv4_tcp_post(void *l4_hdr, u16 datagram_len, void *arg)
{
	struct tcphdr *hdr = l4_hdr;
	struct ipv4_pair *pair4 = arg;

	hdr->check = csum_tcpudp_magic(pair4->remote.address.s_addr, pair4->local.address.s_addr,
			datagram_len, IPPROTO_TCP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int ipv4_udp_post(void *l4_hdr, u16 datagram_len, void *arg)
{
	struct udphdr *hdr = l4_hdr;
	struct ipv4_pair *pair4 = arg;

	hdr->check = csum_tcpudp_magic(pair4->remote.address.s_addr, pair4->local.address.s_addr,
			datagram_len, IPPROTO_UDP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int ipv4_icmp_post(void *l4_hdr, u16 datagram_len, void *arg)
{
	struct icmphdr *hdr = l4_hdr;
	hdr->checksum = ip_compute_csum(hdr, datagram_len);
	return 0;
}

int ipv6_tcp_post(void *l4_hdr, u16 datagram_len, void *arg)
{
	struct tcphdr *hdr = l4_hdr;
	struct ipv6_pair *pair6 = arg;

	hdr->check = csum_ipv6_magic(&pair6->remote.address, &pair6->local.address, datagram_len,
			NEXTHDR_TCP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int ipv6_udp_post(void *l4_hdr, u16 datagram_len, void *arg)
{
	struct udphdr *hdr = l4_hdr;
	struct ipv6_pair *pair6 = arg;

	hdr->check = csum_ipv6_magic(&pair6->remote.address, &pair6->local.address, datagram_len,
			NEXTHDR_UDP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int ipv6_icmp_post(void *l4_hdr, u16 datagram_len, void *arg)
{
	struct icmp6hdr *hdr = l4_hdr;
	struct ipv6_pair *pair6 = arg;

	hdr->icmp6_cksum = csum_ipv6_magic(&pair6->remote.address, &pair6->local.address, datagram_len,
			NEXTHDR_ICMP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int create_skb(int (*l3_hdr_cb)(void *, u16, u8, void *), int l3_hdr_type, int l3_hdr_len,
		int (*l4_hdr_cb)(void *, int, u16, void *), int l4_hdr_type, int l4_hdr_len,
		int (*payload_cb)(void *, u16), u16 payload_len,
		int (*l4_post_cb)(void *, u16, void *),
		struct sk_buff **result, void *arg)
{
	struct sk_buff *skb;
	int datagram_len = l4_hdr_len + payload_len;
	int error;

	skb = alloc_skb(LL_MAX_HEADER + l3_hdr_len + datagram_len, GFP_ATOMIC);
	if (!skb) {
		log_err(ERR_ALLOC_FAILED, "New packet allocation failed.");
		return -ENOMEM;
	}
	skb->protocol = htons(l3_hdr_type);

	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, l3_hdr_len + l4_hdr_len + payload_len);

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3_hdr_len);

	error = l3_hdr_cb(skb_network_header(skb), datagram_len, l4_hdr_type, arg);
	if (error)
		goto failure;
	error = l4_hdr_cb(skb_transport_header(skb), l3_hdr_type, datagram_len, arg);
	if (error)
		goto failure;
	error = payload_cb(skb_transport_header(skb) + l4_hdr_len, payload_len);
	if (error)
		goto failure;

	error = l4_post_cb(skb_transport_header(skb), datagram_len, arg);
	if (error)
		goto failure;

	*result = skb;

	return 0;

failure:
	kfree_skb(skb);
	return error;
}

int create_skb_ipv6_udp(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN,
			init_udp_hdr, NEXTHDR_UDP, UDP_HDR_LEN,
			init_payload_normal, payload_len,
			ipv6_udp_post,
			result, pair6);
}

int create_skb_ipv6_tcp(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN,
			init_tcp_hdr, NEXTHDR_TCP, TCP_HDR_LEN,
			init_payload_normal, payload_len,
			ipv6_tcp_post,
			result, pair6);
}

int create_skb_ipv6_icmp_info(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN,
			init_icmp6_hdr_info, NEXTHDR_ICMP, ICMP6_HDR_LEN,
			init_payload_normal, payload_len,
			ipv6_icmp_post,
			result, pair6);
}

int create_skb_ipv6_icmp_error(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN,
			init_icmp6_hdr_error, NEXTHDR_ICMP, ICMP6_HDR_LEN,
			init_payload_inner_ipv6, payload_len,
			ipv6_icmp_post,
			result, pair6);
}

int create_skb_ipv4_udp(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN,
			init_udp_hdr, IPPROTO_UDP, UDP_HDR_LEN,
			init_payload_normal, payload_len,
			ipv4_udp_post,
			result, pair4);
}

int create_skb_ipv4_tcp(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN,
			init_tcp_hdr, IPPROTO_TCP, TCP_HDR_LEN,
			init_payload_normal, payload_len,
			ipv4_tcp_post,
			result, pair4);
}

int create_skb_ipv4_icmp_info(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN,
			init_icmp4_hdr_info, IPPROTO_ICMP, ICMP4_HDR_LEN,
			init_payload_normal, payload_len,
			ipv4_icmp_post,
			result, pair4);
}

int create_skb_ipv4_icmp_error(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN,
			init_icmp4_hdr_error, IPPROTO_ICMP, ICMP4_HDR_LEN,
			init_payload_inner_ipv4, payload_len,
			ipv4_icmp_post,
			result, pair4);
}

int create_skb_ipv4_udp_fragment(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN,
			init_empty_hdr, IPPROTO_UDP, 0,
			init_payload_normal, payload_len,
			empty_post,
			result, pair4);
}

int create_skb_ipv4_tcp_fragment(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN,
			init_empty_hdr, IPPROTO_TCP, 0,
			init_payload_normal, payload_len,
			empty_post,
			result, pair4);
}

int create_skb_ipv4_icmp_info_fragment(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN,
			init_empty_hdr, IPPROTO_ICMP, 0,
			init_payload_normal, payload_len,
			empty_post,
			result, pair4);
}

int create_skb_ipv6_udp_fragment_1(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
			init_udp_hdr, NEXTHDR_UDP, UDP_HDR_LEN,
			init_payload_normal, payload_len,
			ipv6_udp_post,
			result, pair6);
}

int create_skb_ipv6_udp_fragment_n(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
			init_empty_hdr, NEXTHDR_UDP, 0,
			init_payload_normal, payload_len,
			empty_post,
			result, pair6);
}

int create_skb_ipv6_tcp_fragment_1(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
			init_tcp_hdr, NEXTHDR_TCP, TCP_HDR_LEN,
			init_payload_normal, payload_len,
			ipv6_tcp_post,
			result, pair6);
}

int create_skb_ipv6_tcp_fragment_n(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
			init_empty_hdr, NEXTHDR_TCP, 0,
			init_payload_normal, payload_len,
			empty_post,
			result, pair6);
}

int create_skb_ipv6_icmp_info_fragment_1(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
			init_icmp6_hdr_info, NEXTHDR_ICMP, ICMP6_HDR_LEN,
			init_payload_normal, payload_len,
			ipv6_icmp_post,
			result, pair6);
}

int create_skb_ipv6_icmp_info_fragment_n(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len)
{
	return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
			init_empty_hdr, NEXTHDR_ICMP, 0,
			init_payload_normal, payload_len,
			empty_post,
			result, pair6);
}

/* Packet stuff */
bool create_packet_ipv4_udp_fragmented_disordered(struct ipv4_pair *pair4,
															struct packet **pkt)
{
	struct sk_buff *skb1, *skb2, *skb3;
	struct iphdr *hdr4;
	int error;
	bool success = true;

	/* First packet arrives. */
	error = create_skb_ipv4_udp_fragment(pair4, &skb3, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb3);
	hdr4->frag_off = build_ipv4_frag_off_field(false, false, sizeof(struct udphdr) + 200);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= VER_STOLEN == pkt_from_skb(skb3, pkt);

	/* Second packet arrives. */
	error = create_skb_ipv4_udp_fragment(pair4, &skb2, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb2);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, sizeof(struct udphdr) + 100);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= VER_STOLEN == pkt_from_skb(skb2, pkt);

	/* Third and final packet arrives. */
	error = create_skb_ipv4_udp(pair4, &skb1, 100);
	if (error)
		return false;
	hdr4 = ip_hdr(skb1);
	hdr4->frag_off = build_ipv4_frag_off_field(false, true, 0);
	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	success &= VER_CONTINUE == pkt_from_skb(skb1, pkt);

	return success;
}

bool create_packet_ipv6_udp_fragmented_disordered(struct ipv6_pair *pair6,
															struct packet **pkt)
{
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv6hdr *hdr6;
	struct frag_hdr *hdr_frag;
	u32 id1 = 1234;
	int error;
	bool success = true;

	/* First packet arrives. */
	error = create_skb_ipv6_udp_fragment_n(pair6, &skb3, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb3);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(200+sizeof(struct udphdr), false);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= VER_STOLEN == pkt_from_skb(skb3, pkt);

	/* Second packet arrives. */
	error = create_skb_ipv6_udp_fragment_n(pair6, &skb2, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb2);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(100+sizeof(struct udphdr), true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= VER_STOLEN == pkt_from_skb(skb2, pkt);

	/* Third and final packet arrives. */
	error = create_skb_ipv6_udp_fragment_1(pair6, &skb1, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb1);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= VER_CONTINUE == pkt_from_skb(skb1, pkt);

	return success;
}

bool create_packet_ipv6_tcp_fragmented_disordered(struct ipv6_pair *pair6,
															struct packet **pkt)
{
	struct sk_buff *skb1, *skb2, *skb3;
	struct ipv6hdr *hdr6;
	struct frag_hdr *hdr_frag;
	u32 id1 = 1234;
	int error;
	bool success = true;

	/* First packet arrives. */
	error = create_skb_ipv6_tcp_fragment_n(pair6, &skb3, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb3);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(200+sizeof(struct tcphdr), false);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= VER_STOLEN == pkt_from_skb(skb3, pkt);

	/* Second packet arrives. */
	error = create_skb_ipv6_tcp_fragment_n(pair6, &skb2, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb2);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(100+sizeof(struct tcphdr), true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= VER_STOLEN == pkt_from_skb(skb2, pkt);

	/* Third and final packet arrives. */
	error = create_skb_ipv6_tcp_fragment_1(pair6, &skb1, 100);
	if (error)
		return false;
	hdr6 = ipv6_hdr(skb1);
	hdr_frag = (struct frag_hdr *) (hdr6 + 1);
	hdr_frag->frag_off = build_ipv6_frag_off_field(0, true);
	hdr_frag->identification = cpu_to_be32(id1);

	success &= VER_CONTINUE == pkt_from_skb(skb1, pkt);

	return success;
}
