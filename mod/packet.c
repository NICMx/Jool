#include "nat64/mod/packet.h"
#include "nat64/comm/types.h"
#include "nat64/mod/ipv6_hdr_iterator.h"

//#include <linux/list.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <net/ipv6.h>


#define MIN_IPV6_HDR_LEN sizeof(struct ipv6hdr)
#define MIN_IPV4_HDR_LEN sizeof(struct iphdr)
#define MIN_TCP_HDR_LEN sizeof(struct tcphdr)
#define MIN_UDP_HDR_LEN sizeof(struct udphdr)
#define MIN_ICMP6_HDR_LEN sizeof(struct icmp6hdr)
#define MIN_ICMP4_HDR_LEN sizeof(struct icmphdr)


void frag_init(struct fragment *frag)
{
	memset(frag, 0, sizeof(*frag));
	INIT_LIST_HEAD(&frag->next);
}

struct ipv6hdr *frag_get_ipv6_hdr(struct fragment *frag)
{
	return frag->l3_hdr.ptr;
}

struct iphdr *frag_get_ipv4_hdr(struct fragment *frag)
{
	return frag->l3_hdr.ptr;
}

struct tcphdr *frag_get_tcp_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

struct udphdr *frag_get_udp_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

struct icmp6hdr *frag_get_icmp6_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

struct icmphdr *frag_get_icmp4_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

/**
 * Joins out.l3_hdr, out.l4_hdr and out.payload into a single packet, placing the result in
 * out.skb.
 */
enum verdict frag_create_skb(struct fragment *frag)
{
	struct sk_buff *new_skb;
	__u16 head_room = 0, tail_room = 0;

//	TODO
//	spin_lock_bh(&config_lock);
//	head_room = config.skb_head_room;
//	tail_room = config.skb_tail_room;
//	spin_unlock_bh(&config_lock);

	new_skb = alloc_skb(head_room /* user's reserved. */
			+ LL_MAX_HEADER /* kernel's reserved + layer 2. */
			+ frag->l3_hdr.len /* layer 3. */
			+ frag->l4_hdr.len /* layer 4. */
			+ frag->payload.len /* packet data. */
			+ tail_room, /* user's reserved+. */
			GFP_ATOMIC);
	if (!new_skb) {
		log_err(ERR_ALLOC_FAILED, "New packet allocation failed.");
		return VER_DROP;
	}
	frag->skb = new_skb;

	skb_reserve(new_skb, head_room + LL_MAX_HEADER);
	skb_put(new_skb, frag->l3_hdr.len + frag->l4_hdr.len + frag->payload.len);

	skb_reset_mac_header(new_skb);
	skb_reset_network_header(new_skb);
	skb_set_transport_header(new_skb, frag->l3_hdr.len);

	memcpy(skb_network_header(new_skb), frag->l3_hdr.ptr, frag->l3_hdr.len);
	memcpy(skb_transport_header(new_skb), frag->l4_hdr.ptr, frag->l4_hdr.len);
	memcpy(skb_transport_header(new_skb) + frag->l4_hdr.len, frag->payload.ptr, frag->payload.len);

	if (!frag->l3_hdr.ptr_belongs_to_skb)
		kfree(frag->l3_hdr.ptr);
	if (!frag->l4_hdr.ptr_belongs_to_skb)
		kfree(frag->l4_hdr.ptr);
	if (!frag->payload.ptr_belongs_to_skb)
		kfree(frag->payload.ptr);

	frag->l3_hdr.ptr = skb_network_header(new_skb);
	frag->l4_hdr.ptr = skb_transport_header(new_skb);
	frag->payload.ptr = skb_transport_header(new_skb) + frag->l4_hdr.len;

	frag->l3_hdr.ptr_belongs_to_skb = true;
	frag->l4_hdr.ptr_belongs_to_skb = true;
	frag->payload.ptr_belongs_to_skb = true;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV4:
		new_skb->protocol = htons(ETH_P_IP);
		break;
	case L3PROTO_IPV6:
		new_skb->protocol = htons(ETH_P_IPV6);
		break;
	default:
		log_err(ERR_L3PROTO, "Invalid protocol type: %u", frag->l3_hdr.proto);
		return VER_DROP;
	}

	return VER_CONTINUE;
}

void frag_kfree(struct fragment *frag)
{
	if (frag->skb)
		kfree_skb(frag->skb);
	if (frag->l3_hdr.ptr_belongs_to_skb)
		kfree(frag->l3_hdr.ptr);
	if (frag->l4_hdr.ptr_belongs_to_skb)
		kfree(frag->l4_hdr.ptr);
	if (frag->payload.ptr_belongs_to_skb)
		kfree(frag->payload.ptr);

	list_del(&frag->next);
}

static enum verdict validate_lengths_tcp(struct sk_buff *skb, u16 l3_hdr_len)
{
	if (skb->len < l3_hdr_len + MIN_TCP_HDR_LEN) {
		log_debug("Packet is too small to contain a basic TCP header.");
		return VER_DROP;
	}

	if (skb->len < l3_hdr_len + tcp_hdrlen(skb)) {
		log_debug("Packet is too small to contain a TCP header.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static enum verdict validate_lengths_udp(struct sk_buff *skb, u16 l3_hdr_len)
{
	u16 datagram_len;

	if (skb->len < l3_hdr_len + MIN_UDP_HDR_LEN) {
		log_debug("Packet is too small to contain a UDP header.");
		return VER_DROP;
	}

	datagram_len = be16_to_cpu(udp_hdr(skb)->len);
	if (skb->len != l3_hdr_len + datagram_len) {
		log_debug("The network header's length is not consistent with the UDP header's length.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static enum verdict validate_lengths_icmp6(struct sk_buff *skb, u16 l3_hdr_len)
{
	if (skb->len < l3_hdr_len + MIN_ICMP6_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv6 header.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static enum verdict validate_lengths_icmp4(struct sk_buff *skb, u16 l3_hdr_len)
{
	if (skb->len < l3_hdr_len + MIN_ICMP4_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMP header.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static enum verdict validate_csum_ipv6(__sum16 *pkt_csum, struct sk_buff *skb,
		unsigned int datagram_len, int l4_proto)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);
	__sum16 tmp;
	__sum16 computed_csum;

	tmp = *pkt_csum;
	*pkt_csum = 0;
	computed_csum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr, datagram_len, l4_proto,
			csum_partial(skb_transport_header(skb), datagram_len, 0));
	*pkt_csum = tmp;

	if (tmp != computed_csum) {
		log_warning("Checksum doesn't match (protocol: %d). Expected: %x, actual: %x.", l4_proto,
				computed_csum, tmp);
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static enum verdict validate_csum_tcp6(struct sk_buff *skb, int datagram_len)
{
	struct tcphdr *hdr = tcp_hdr(skb);
	return validate_csum_ipv6(&hdr->check, skb, datagram_len, IPPROTO_TCP);
}

static enum verdict validate_csum_udp6(struct sk_buff *skb, int datagram_len)
{
	struct udphdr *hdr = udp_hdr(skb);
	return validate_csum_ipv6(&hdr->check, skb, datagram_len, IPPROTO_UDP);
}

static enum verdict validate_csum_icmp6(struct sk_buff *skb, int datagram_len)
{
	struct icmp6hdr *hdr = icmp6_hdr(skb);
	return validate_csum_ipv6(&hdr->icmp6_cksum, skb, datagram_len, IPPROTO_ICMPV6);
}

static enum verdict validate_csum_tcp4(struct sk_buff *skb, int datagram_len)
{
	struct tcphdr *hdr = tcp_hdr(skb);
	__sum16 tmp;
	__sum16 computed_csum;

	tmp = hdr->check;
	hdr->check = 0;
	computed_csum = csum_tcpudp_magic(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, datagram_len,
			IPPROTO_TCP, csum_partial(skb_transport_header(skb), datagram_len, 0));
	hdr->check = tmp;

	if (tmp != computed_csum) {
		log_warning("Checksum doesn't match (TCP). Expected: %x, actual: %x.", computed_csum, tmp);
		return VER_DROP;
	}

	return VER_CONTINUE;

}

static enum verdict validate_csum_udp4(struct sk_buff *skb, int datagram_len)
{
	struct udphdr *hdr = udp_hdr(skb);
	__sum16 tmp;
	__sum16 computed_csum;

	if (hdr->check == 0)
		return VER_CONTINUE;

	tmp = hdr->check;
	hdr->check = 0;
	computed_csum = csum_tcpudp_magic(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, datagram_len,
			IPPROTO_UDP, csum_partial(skb_transport_header(skb), datagram_len, 0));
	hdr->check = tmp;

	if (computed_csum == 0)
		computed_csum = 0xFFFF;

	if (tmp != computed_csum) {
		log_warning("Checksum doesn't match (UDP). Expected: %x, actual: %x.", computed_csum, tmp);
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static enum verdict validate_csum_icmp4(struct sk_buff *skb, int datagram_len)
{
	struct icmphdr *hdr = icmp_hdr(skb);
	__sum16 tmp;
	__sum16 computed_csum;

	tmp = hdr->checksum;
	hdr->checksum = 0;
	computed_csum = ip_compute_csum(hdr, datagram_len);
	hdr->checksum = tmp;

	if (tmp != computed_csum) {
		log_warning("Checksum doesn't match (ICMPv4). Expected: %x, actual: %x.",
				computed_csum, tmp);
		return VER_DROP;
	}

	return VER_CONTINUE;
}

enum verdict validate_skb_ipv6(struct sk_buff *skb)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);
	u16 ip6_hdr_len; /* Includes extension headers. */
	u16 datagram_len;
	enum verdict result;

	struct hdr_iterator iterator = HDR_ITERATOR_INIT(ip6_hdr);
	enum hdr_iterator_result iterator_result;

	/*
	if (skb->len < MIN_IPV6_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IPv6 header.");
		return VER_DROP;
	}
	*/
	if (skb->len != MIN_IPV6_HDR_LEN + be16_to_cpu(ip6_hdr->payload_len)) {
		log_debug("The socket buffer's length does not match the IPv6 header's payload lengh field.");
		return VER_DROP;
	}

	iterator_result = hdr_iterator_last(&iterator);
	switch (iterator_result) {
	case HDR_ITERATOR_SUCCESS:
		log_crit(ERR_INVALID_ITERATOR, "Iterator reports there are headers beyond the payload.");
		return VER_DROP;
	case HDR_ITERATOR_END:
		/* Success. */
		break;
	case HDR_ITERATOR_UNSUPPORTED:
		/* RFC 6146 section 5.1. */
		log_info("Packet contains an Authentication or ESP header, which I do not support.");
		return VER_DROP;
	case HDR_ITERATOR_OVERFLOW:
		log_warning("IPv6 extension header analysis ran past the end of the packet. "
				"Packet seems corrupted; ignoring.");
		return VER_DROP;
	default:
		log_crit(ERR_INVALID_ITERATOR, "Unknown header iterator result code: %d.", iterator_result);
		return VER_DROP;
	}

	/* IPv6 header length = transport header offset - IPv6 header offset. */
	ip6_hdr_len = iterator.data - (void *) ip6_hdr;
	datagram_len = skb->len - ip6_hdr_len;

	/*
	 * Set the skb's transport header pointer.
	 * It's yet to be set because the packet hasn't reached the kernel's transport layer.
	 * And despite that, its availability through the rest of the module will be appreciated.
	 */
	skb_set_transport_header(skb, ip6_hdr_len);

	switch (iterator.hdr_type) {
	case NEXTHDR_TCP:
		result = validate_lengths_tcp(skb, ip6_hdr_len);
		if (result != VER_CONTINUE)
			return result;
		result = validate_csum_tcp6(skb, datagram_len);
		if (result != VER_CONTINUE)
			return result;
		break;

	case NEXTHDR_UDP:
		result = validate_lengths_udp(skb, ip6_hdr_len);
		if (result != VER_CONTINUE)
			return result;
		result = validate_csum_udp6(skb, datagram_len);
		if (result != VER_CONTINUE)
			return result;
		break;

	case NEXTHDR_ICMP:
		result = validate_lengths_icmp6(skb, ip6_hdr_len);
		if (result != VER_CONTINUE)
			return result;
		result = validate_csum_icmp6(skb, datagram_len);
		if (result != VER_CONTINUE)
			return result;
		break;

	default:
		log_debug("Packet does not use TCP, UDP or ICMPv6.");
		return VER_DROP;
	}

	return result;
}

enum verdict validate_skb_ipv4(struct sk_buff *skb)
{
	struct iphdr *ip4_hdr = ip_hdr(skb);
	u16 ip4_hdr_len;
	u16 datagram_len;
	enum verdict result;

	/*
	if (skb->len < MIN_IPV4_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IP header.");
		return VER_DROP;
	}
	*/
	if (ip4_hdr->ihl < 5) {
		log_debug("Packet's IHL field is too small.");
		return VER_DROP;
	}
	if (ip_fast_csum((u8 *) ip4_hdr, ip4_hdr->ihl)) {
		log_debug("Packet's IPv4 checksum is incorrect.");
		return VER_DROP;
	}

	ip4_hdr_len = 4 * ip4_hdr->ihl;

	if (skb->len < ip4_hdr_len) {
		log_debug("Packet is too small to contain the IP header + options.");
		return VER_DROP;
	}
	if (skb->len != be16_to_cpu(ip4_hdr->tot_len)) {
		log_debug("The socket buffer's length does not equal the IPv4 header's lengh field.");
		return VER_DROP;
	}

	datagram_len = skb->len - ip4_hdr_len;

	/*
	 * Set the skb's transport header pointer.
	 * It's yet to be set because the packet hasn't reached the kernel's transport layer.
	 * And despite that, its availability through the rest of the module will be appreciated.
	 */
	skb_set_transport_header(skb, ip4_hdr_len);

	switch (ip4_hdr->protocol) {
	case IPPROTO_TCP:
		result = validate_lengths_tcp(skb, ip4_hdr_len);
		if (result != VER_CONTINUE)
			return result;
		result = validate_csum_tcp4(skb, datagram_len);
		if (result != VER_CONTINUE)
			return result;
		break;

	case IPPROTO_UDP:
		result = validate_lengths_udp(skb, ip4_hdr_len);
		if (result != VER_CONTINUE)
			return result;
		result = validate_csum_udp4(skb, datagram_len);
		if (result != VER_CONTINUE)
			return result;
		break;

	case IPPROTO_ICMP:
		result = validate_lengths_icmp4(skb, ip4_hdr_len);
		if (result != VER_CONTINUE)
			return result;
		result = validate_csum_icmp4(skb, datagram_len);
		if (result != VER_CONTINUE)
			return result;
		break;

	default:
		log_debug("Packet does not use TCP, UDP or ICMP.");
		return VER_DROP;
	}

	return result;
}
