#include "nat64/unit/skb_generator.h"
#include "nat64/unit/types.h"
#include "nat64/common/str_utils.h"

#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>


#define IPV4_HDR_LEN sizeof(struct iphdr)
int init_ipv4_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple4,
		bool df, bool mf, u16 frag_offset, u8 ttl)
{
	struct iphdr *hdr = l3_hdr;

	hdr->version = 4;
	hdr->ihl = 5;
	hdr->tos = 0;
	hdr->tot_len = cpu_to_be16(sizeof(*hdr) + payload_len);
	hdr->id = (frag_offset != 0 || mf) ? cpu_to_be16(4321) : 0;
	hdr->frag_off = build_ipv4_frag_off_field(df, mf, frag_offset);
	hdr->ttl = ttl;
	hdr->protocol = nexthdr;
	hdr->saddr = tuple4->src.addr4.l3.s_addr;
	hdr->daddr = tuple4->dst.addr4.l3.s_addr;

	hdr->check = 0;
	hdr->check = ip_fast_csum(hdr, hdr->ihl);

	return 0;
}

#define IPV6_HDR_LEN sizeof(struct ipv6hdr)
int init_ipv6_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple6,
		bool df, bool mf, u16 frag_offset, u8 ttl)
{
	struct ipv6hdr *hdr = l3_hdr;

	hdr->version = 6;
	hdr->priority = 0;
	hdr->flow_lbl[0] = 0;
	hdr->flow_lbl[1] = 0;
	hdr->flow_lbl[2] = 0;
	hdr->payload_len = cpu_to_be16(payload_len);
	hdr->nexthdr = nexthdr;
	hdr->hop_limit = ttl;
	hdr->saddr = tuple6->src.addr6.l3;
	hdr->daddr = tuple6->dst.addr6.l3;

	return 0;
}

#define FRAG_HDR_LEN sizeof(struct frag_hdr)
static int init_ipv6_and_frag_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple6,
		bool df, bool mf, u16 frag_offset, u8 ttl)
{
	struct ipv6hdr *hdr6 = l3_hdr;
	struct frag_hdr *frag_hdr = (struct frag_hdr *) (hdr6 + 1);
	int error;

	error = init_ipv6_hdr(hdr6, FRAG_HDR_LEN + payload_len, NEXTHDR_FRAGMENT, tuple6,
			df, mf, frag_offset, ttl);
	if (error != 0)
		return error;

	frag_hdr->nexthdr = nexthdr;
	frag_hdr->reserved = 0;
	frag_hdr->frag_off = build_ipv6_frag_off_field(frag_offset, mf);
	frag_hdr->identification = cpu_to_be32(4321);

	return 0;
}

#define UDP_HDR_LEN sizeof(struct udphdr)
static int init_udp_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, struct tuple *tuple)
{
	struct udphdr *hdr = l4_hdr;

	switch (l3_hdr_type) {
	case ETH_P_IPV6:
		hdr->source = cpu_to_be16(tuple->src.addr6.l4);
		hdr->dest = cpu_to_be16(tuple->dst.addr6.l4);
		break;
	case ETH_P_IP:
		hdr->source = cpu_to_be16(tuple->src.addr4.l4);
		hdr->dest = cpu_to_be16(tuple->dst.addr4.l4);
		break;
	default:
		log_err("Unsupported network protocol: %d.", l3_hdr_type);
		return -EINVAL;
	}

	hdr->len = cpu_to_be16(datagram_len);
	hdr->check = 0;

	return 0;
}

#define TCP_HDR_LEN sizeof(struct tcphdr)
int init_tcp_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, struct tuple *tuple)
{
	struct tcphdr *hdr = l4_hdr;

	switch (l3_hdr_type) {
	case ETH_P_IPV6:
		hdr->source = cpu_to_be16(tuple->src.addr6.l4);
		hdr->dest = cpu_to_be16(tuple->dst.addr6.l4);
		break;
	case ETH_P_IP:
		hdr->source = cpu_to_be16(tuple->src.addr4.l4);
		hdr->dest = cpu_to_be16(tuple->dst.addr4.l4);
		break;
	default:
		log_err("Unsupported network protocol: %d.", l3_hdr_type);
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
	hdr->syn = 1;
	hdr->fin = 0;
	hdr->window = cpu_to_be16(3233);
	hdr->check = 0;
	hdr->urg_ptr = cpu_to_be16(9865);

	return 0;
}

#define ICMP4_HDR_LEN sizeof(struct icmphdr)
static int init_icmp4_hdr_info(void *l4_hdr, int l3_hdr_type, u16 datagram_len,
		struct tuple *tuple4)
{
	struct icmphdr *hdr = l4_hdr;

	hdr->type = ICMP_ECHO;
	hdr->code = 0;
	hdr->checksum = 0;
	hdr->un.echo.id = cpu_to_be16(tuple4->src.addr4.l4);
	hdr->un.echo.sequence = cpu_to_be16(2000);

	return 0;
}

static int init_icmp4_hdr_error(void *l4_hdr, int l3_hdr_type, u16 datagram_len,
		struct tuple *tuple4)
{
	struct icmphdr *hdr = l4_hdr;

	hdr->type = ICMP_DEST_UNREACH;
	hdr->code = ICMP_FRAG_NEEDED;
	hdr->checksum = 0;
	hdr->un.frag.__unused = cpu_to_be16(0);
	hdr->un.frag.mtu = cpu_to_be16(1500);

	return 0;
}

#define ICMP6_HDR_LEN sizeof(struct icmp6hdr)
static int init_icmp6_hdr_info(void *l4_hdr, int l3_hdr_type, u16 datagram_len,
		struct tuple *tuple6)
{
	struct icmp6hdr *hdr = l4_hdr;

	hdr->icmp6_type = ICMPV6_ECHO_REQUEST;
	hdr->icmp6_code = 0;
	hdr->icmp6_cksum = 0;
	hdr->icmp6_dataun.u_echo.identifier = cpu_to_be16(tuple6->src.addr6.l4);
	hdr->icmp6_dataun.u_echo.sequence = cpu_to_be16(2000);

	return 0;
}

static int init_icmp6_hdr_error(void *l4_hdr, int l3_hdr_type, u16 datagram_len,
		struct tuple *tuple6)
{
	struct icmp6hdr *hdr = l4_hdr;

	hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
	hdr->icmp6_code = 0;
	hdr->icmp6_cksum = 0;
	hdr->icmp6_mtu = cpu_to_be32(1500);

	return 0;
}

static int init_empty_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, struct tuple *tuple)
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
	struct ipv6hdr tmp_hdr_ipv6;
	struct tcphdr tmp_hdr_tcp;
	unsigned char *inner_payload;
	struct tuple tuple6;
	int error;

	if (payload_len <= 0)
		return 0; /* Nothing to do here. */

	error = init_ipv6_tuple(&tuple6, "1::1", 50080, "64::192.0.2.5", 51234, L4PROTO_TCP);
	if (error)
		return error;

	hdr_ipv6 = target;
	hdr_tcp = (struct tcphdr *) (hdr_ipv6 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	error = init_ipv6_hdr(&tmp_hdr_ipv6, 1300, NEXTHDR_TCP, &tuple6, true, false, 0, 32);
	if (error)
		return error;

	if (payload_len >= IPV6_HDR_LEN) {
		memcpy(hdr_ipv6, &tmp_hdr_ipv6, IPV6_HDR_LEN);
		payload_len -= IPV6_HDR_LEN;
	} else {
		memcpy(hdr_ipv6, &tmp_hdr_ipv6, payload_len);
		goto end;
	}

	error = init_tcp_hdr(&tmp_hdr_tcp, ETH_P_IPV6, 1300, &tuple6);
	if (error)
		return error;

	if (payload_len >= TCP_HDR_LEN) {
		memcpy(hdr_tcp, &tmp_hdr_tcp, TCP_HDR_LEN);
		payload_len -= TCP_HDR_LEN;
	} else {
		memcpy(hdr_tcp, &tmp_hdr_tcp, payload_len);
		goto end;
	}

	error = init_payload_normal(inner_payload, payload_len);
	if (error)
		return error;

	hdr_tcp->check = csum_ipv6_magic(&hdr_ipv6->saddr, &hdr_ipv6->daddr,
			sizeof(*hdr_tcp) + payload_len, NEXTHDR_TCP,
			csum_partial(hdr_tcp, sizeof(*hdr_tcp) + payload_len, 0));
	/* Fall through. */

end:
	return 0;
}

static int init_payload_inner_ipv4(void *target, u16 payload_len)
{
	struct iphdr *hdr_ipv4;
	struct tcphdr *hdr_tcp;
	struct iphdr tmp_hdr_ipv4;
	struct tcphdr tmp_hdr_tcp;
	unsigned char *inner_payload;
	struct tuple tuple4;
	int error;

	if (payload_len <= 0)
		return 0; /* Nothing to do here. */

	error = init_ipv4_tuple(&tuple4, "192.0.2.5", 1234, "192.0.2.2", 80, L4PROTO_TCP);
	if (error)
		return error;

	hdr_ipv4 = target;
	hdr_tcp = (struct tcphdr *) (hdr_ipv4 + 1);
	inner_payload = (unsigned char *) (hdr_tcp + 1);

	error = init_ipv4_hdr(&tmp_hdr_ipv4, 1300, IPPROTO_TCP, &tuple4, true, false, 0, 32);
	if (error)
		return error;

	if (payload_len >= IPV4_HDR_LEN) {
		memcpy(hdr_ipv4, &tmp_hdr_ipv4, IPV4_HDR_LEN);
		payload_len -= IPV4_HDR_LEN;
	} else {
		memcpy(hdr_ipv4, &tmp_hdr_ipv4, payload_len);
		goto end;
	}

	error = init_tcp_hdr(&tmp_hdr_tcp, ETH_P_IP, 1300, &tuple4);
	if (error)
		return error;

	if (payload_len >= TCP_HDR_LEN) {
		memcpy(hdr_tcp, &tmp_hdr_tcp, TCP_HDR_LEN);
		payload_len -= TCP_HDR_LEN;
	} else {
		memcpy(hdr_tcp, &tmp_hdr_tcp, payload_len);
		goto end;
	}

	error = init_payload_normal(inner_payload, payload_len);
	if (error)
		return error;

	hdr_tcp->check = csum_tcpudp_magic(hdr_ipv4->saddr, hdr_ipv4->daddr,
			sizeof(*hdr_tcp) + payload_len, IPPROTO_TCP,
			csum_partial(hdr_tcp, sizeof(*hdr_tcp) + payload_len, 0));
	/* Fall through. */

end:
	return 0;
}

static int empty_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple)
{
	return 0;
}

int ipv4_tcp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple4)
{
	struct tcphdr *hdr = l4_hdr;

	hdr->check = csum_tcpudp_magic(tuple4->src.addr4.l3.s_addr, tuple4->dst.addr4.l3.s_addr,
			datagram_len, IPPROTO_TCP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int ipv4_udp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple4)
{
	struct udphdr *hdr = l4_hdr;

	hdr->check = csum_tcpudp_magic(tuple4->src.addr4.l3.s_addr, tuple4->dst.addr4.l3.s_addr,
			datagram_len, IPPROTO_UDP, csum_partial(l4_hdr, datagram_len, 0));

	if (hdr->check == 0)
		hdr->check = CSUM_MANGLED_0;

	return 0;
}

static int ipv4_icmp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple4)
{
	struct icmphdr *hdr = l4_hdr;
	hdr->checksum = ip_compute_csum(hdr, datagram_len);
	return 0;
}

int ipv6_tcp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple6)
{
	struct tcphdr *hdr = l4_hdr;

	hdr->check = csum_ipv6_magic(&tuple6->src.addr6.l3, &tuple6->dst.addr6.l3, datagram_len,
			NEXTHDR_TCP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int ipv6_udp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple6)
{
	struct udphdr *hdr = l4_hdr;

	hdr->check = csum_ipv6_magic(&tuple6->src.addr6.l3, &tuple6->dst.addr6.l3, datagram_len,
			NEXTHDR_UDP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int ipv6_icmp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple6)
{
	struct icmp6hdr *hdr = l4_hdr;

	hdr->icmp6_cksum = csum_ipv6_magic(&tuple6->src.addr6.l3, &tuple6->dst.addr6.l3, datagram_len,
			NEXTHDR_ICMP, csum_partial(l4_hdr, datagram_len, 0));

	return 0;
}

static int create_skb(int (*l3_hdr_fn)(void *, u16, u8, struct tuple *, bool, bool, u16, u8),
		int l3_hdr_type, int l3_hdr_len, bool df, bool mf, u16 frag_offset, u8 ttl,
		int (*l4_hdr_fn)(void *, int, u16, struct tuple *),
		int l4_hdr_type, int l4_hdr_len, int l4_total_len,
		int (*payload_fn)(void *, u16), u16 payload_len,
		int (*l4_post_fn)(void *, u16, struct tuple *),
		struct sk_buff **result, struct tuple *tuple)
{
	struct sk_buff *skb;
	int datagram_len = l4_hdr_len + payload_len;
	int error;

	skb = alloc_skb(LL_MAX_HEADER + l3_hdr_len + datagram_len, GFP_ATOMIC);
	if (!skb) {
		log_err("New packet allocation failed.");
		return -ENOMEM;
	}
	skb->protocol = htons(l3_hdr_type);

	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, l3_hdr_len + l4_hdr_len + payload_len);

	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3_hdr_len);

	error = l3_hdr_fn(skb_network_header(skb), datagram_len, l4_hdr_type, tuple, df, mf,
			frag_offset, ttl);
	if (error)
		goto failure;
	error = l4_hdr_fn(skb_transport_header(skb), l3_hdr_type, l4_total_len, tuple);
	if (error)
		goto failure;

	error = payload_fn(skb_transport_header(skb) + l4_hdr_len, payload_len);
	if (error)
		goto failure;
	error = l4_post_fn(skb_transport_header(skb), datagram_len, tuple);
	if (error)
		goto failure;

	switch (l3_hdr_type) {
	case ETH_P_IP:
		error = pkt_init_ipv4(skb);
		break;
	case ETH_P_IPV6:
		error = pkt_init_ipv6(skb);
		break;
	default:
		error = -EINVAL;
	}
	if (error)
		goto failure;

	*result = skb;

	return 0;

failure:
	kfree_skb(skb);
	return error;
}

static int init_custom_payload(void *target, u16 *payload_array, u16 payload_len)
{
	unsigned char *payload = target;
	u16 i;

	for (i = 0; i < payload_len; i++)
		payload[i] = payload_array[i];

	return 0;
}

static int create_skb_custom_payload(
		int (*l3_hdr_fn)(void *, u16, u8, struct tuple *, bool, bool, u16, u8),
		int l3_hdr_type, int l3_hdr_len, bool df, bool mf, u16 frag_offset, u8 ttl,
		int (*l4_hdr_fn)(void *, int, u16, struct tuple *),
		int l4_hdr_type, int l4_hdr_len, int l4_total_len,
		u16 *payload_array, u16 payload_len,
		int (*l4_post_fn)(void *, u16, struct tuple *),
		struct sk_buff **result, struct tuple *tuple)
{
	int error = 0;
	error = create_skb(l3_hdr_fn, l3_hdr_type, l3_hdr_len, df, mf, frag_offset, ttl,
			l4_hdr_fn,l4_hdr_type, l4_hdr_len, l4_total_len,
			init_payload_normal, payload_len,
			empty_post,
			result, tuple);
	if (error)
		goto failure;

	error = init_custom_payload(skb_transport_header(*result) + l4_hdr_len,
			payload_array, payload_len);
	if (error)
		goto failure;

	error = l4_post_fn(skb_transport_header(*result), l4_hdr_len + payload_len, tuple);
	if (error)
		goto failure;

	return 0;

failure:
	kfree_skb(*result);
	return error;
}

int create_skb6_upd_custom_payload(struct tuple *tuple6, struct sk_buff **result, u16 *payload_array,
		u16 payload_len, u8 ttl)
{
	return create_skb_custom_payload(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN, true, false, 0, ttl,
			init_udp_hdr, NEXTHDR_UDP, UDP_HDR_LEN, UDP_HDR_LEN + payload_len,
			payload_array, payload_len,
			ipv6_udp_post,
			result, tuple6);
}

int create_skb4_upd_custom_payload(struct tuple *tuple4, struct sk_buff **result, u16 *payload_array,
		u16 payload_len, u8 ttl)
{
	return create_skb_custom_payload(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, true, false, 0, ttl,
			init_udp_hdr, IPPROTO_UDP, UDP_HDR_LEN, UDP_HDR_LEN + payload_len,
			payload_array, payload_len,
			ipv4_udp_post,
			result, tuple4);
}

int create_skb6_udp(struct tuple *tuple6, struct sk_buff **result, u16 payload_len, u8 ttl)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN, true, false, 0, ttl,
			init_udp_hdr, NEXTHDR_UDP, UDP_HDR_LEN, UDP_HDR_LEN + payload_len,
			init_payload_normal, payload_len,
			ipv6_udp_post,
			result, tuple6);
}

int create_skb6_tcp(struct tuple *tuple6, struct sk_buff **result, u16 payload_len, u8 ttl)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN, true, false, 0, ttl,
			init_tcp_hdr, NEXTHDR_TCP, TCP_HDR_LEN, TCP_HDR_LEN + payload_len,
			init_payload_normal, payload_len,
			ipv6_tcp_post,
			result, tuple6);
}

int create_skb6_icmp_info(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u8 ttl)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN, true, false, 0, ttl,
			init_icmp6_hdr_info, NEXTHDR_ICMP, ICMP6_HDR_LEN, ICMP6_HDR_LEN + payload_len,
			init_payload_normal, payload_len,
			ipv6_icmp_post,
			result, tuple6);
}

int create_skb6_icmp_error(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u8 ttl)
{
	return create_skb(init_ipv6_hdr, ETH_P_IPV6, IPV6_HDR_LEN, true, false, 0, ttl,
			init_icmp6_hdr_error, NEXTHDR_ICMP, ICMP6_HDR_LEN, ICMP6_HDR_LEN + payload_len,
			init_payload_inner_ipv6, payload_len,
			ipv6_icmp_post,
			result, tuple6);
}

int create_skb4_udp(struct tuple *tuple4, struct sk_buff **result, u16 payload_len, u8 ttl)
{
	return create_skb4_udp_frag(tuple4, result, payload_len,
			UDP_HDR_LEN + payload_len, true, false, 0, ttl);
}

int create_skb4_tcp(struct tuple *tuple4, struct sk_buff **result, u16 payload_len, u8 ttl)
{
	return create_skb4_tcp_frag(tuple4, result, payload_len,
			TCP_HDR_LEN + payload_len, true, false, 0, ttl);
}

int create_skb4_icmp_info(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u8 ttl)
{
	return create_skb4_icmp_info_frag(tuple4, result, payload_len,
			ICMP4_HDR_LEN + payload_len, true, false, 0, ttl);
}

int create_skb4_icmp_error(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u8 ttl)
{
	return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, true, false, 0, ttl,
			init_icmp4_hdr_error, IPPROTO_ICMP, ICMP4_HDR_LEN, ICMP4_HDR_LEN + payload_len,
			init_payload_inner_ipv4, payload_len,
			ipv4_icmp_post,
			result, tuple4);
}

int create_skb4_udp_frag(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl)
{
	if (frag_offset == 0)
		return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, df, mf, frag_offset, ttl,
				init_udp_hdr, IPPROTO_UDP, UDP_HDR_LEN, total_l4_len,
				init_payload_normal, payload_len,
				ipv4_udp_post,
				result, tuple4);
	else
		return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, df, mf, frag_offset, ttl,
				init_empty_hdr, IPPROTO_UDP, 0, total_l4_len,
				init_payload_normal, payload_len,
				empty_post,
				result, tuple4);
}

int create_skb4_tcp_frag(struct tuple *tuple4, struct sk_buff **result,
		u16 payload_len, u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl)
{
	if (frag_offset == 0)
		return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, df, mf, frag_offset, ttl,
				init_tcp_hdr, IPPROTO_TCP, TCP_HDR_LEN, total_l4_len,
				init_payload_normal, payload_len,
				ipv4_tcp_post,
				result, tuple4);
	else
		return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, df, mf, frag_offset, ttl,
				init_empty_hdr, IPPROTO_TCP, 0, total_l4_len,
				init_payload_normal, payload_len,
				empty_post,
				result, tuple4);
}

int create_skb4_icmp_info_frag(struct tuple *tuple4, struct sk_buff **result,
		u16 payload_len, u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl)
{
	if (frag_offset == 0)
		return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, df, mf, frag_offset, ttl,
				init_icmp4_hdr_info, IPPROTO_ICMP, ICMP4_HDR_LEN, total_l4_len,
				init_payload_normal, payload_len,
				ipv4_icmp_post,
				result, tuple4);
	else
		return create_skb(init_ipv4_hdr, ETH_P_IP, IPV4_HDR_LEN, df, mf, frag_offset, ttl,
				init_empty_hdr, IPPROTO_ICMP, 0, total_l4_len,
				init_payload_normal, payload_len,
				empty_post,
				result, tuple4);
}

int create_skb6_udp_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl)
{
	if (frag_offset == 0)
		return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
				df, mf, frag_offset, ttl,
				init_udp_hdr, NEXTHDR_UDP, UDP_HDR_LEN, total_l4_len,
				init_payload_normal, payload_len,
				ipv6_udp_post,
				result, tuple6);
	else
		return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
				df, mf, frag_offset, ttl,
				init_empty_hdr, NEXTHDR_UDP, 0, total_l4_len,
				init_payload_normal, payload_len,
				empty_post,
				result, tuple6);
}

int create_skb6_tcp_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl)
{
	if (frag_offset == 0)
		return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
				df, mf, frag_offset, ttl,
				init_tcp_hdr, NEXTHDR_TCP, TCP_HDR_LEN, total_l4_len,
				init_payload_normal, payload_len,
				ipv6_tcp_post,
				result, tuple6);
	else
		return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
				df, mf, frag_offset, ttl,
				init_empty_hdr, NEXTHDR_TCP, 0, total_l4_len,
				init_payload_normal, payload_len,
				empty_post,
				result, tuple6);
}

int create_skb6_icmp_info_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl)
{
	if (frag_offset == 0)
		return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
				df, mf, frag_offset, ttl,
				init_icmp6_hdr_info, NEXTHDR_ICMP, ICMP6_HDR_LEN, total_l4_len,
				init_payload_normal, payload_len,
				ipv6_icmp_post,
				result, tuple6);
	else
		return create_skb(init_ipv6_and_frag_hdr, ETH_P_IPV6, IPV6_HDR_LEN + FRAG_HDR_LEN,
				df, mf, frag_offset, ttl,
				init_empty_hdr, NEXTHDR_ICMP, 0, total_l4_len,
				init_payload_normal, payload_len,
				empty_post,
				result, tuple6);
}

int create_tcp_packet(struct sk_buff **skb, l3_protocol l3_proto, bool syn, bool rst, bool fin)
{
	struct tcphdr *hdr_tcp;
	struct tuple tuple;
	int error;

	switch (l3_proto) {
	case L3PROTO_IPV4:
		error = init_ipv4_tuple(&tuple, "8.7.6.5", 8765, "5.6.7.8", 5678, L4PROTO_TCP);
		if (error)
			return error;
		error = create_skb4_tcp(&tuple, skb, 100, 32);
		if (error)
			return error;
		break;
	case L3PROTO_IPV6:
		error = init_ipv6_tuple(&tuple, "1::2", 1212, "3::4", 3434, L4PROTO_TCP);
		if (error)
			return error;
		error = create_skb6_tcp(&tuple, skb, 100, 32);
		if (error)
			return error;
		break;
	}

	hdr_tcp = tcp_hdr(*skb);
	hdr_tcp->syn = syn;
	hdr_tcp->rst = rst;
	hdr_tcp->fin = fin;

	return 0;
}
