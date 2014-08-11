#include "nat64/mod/packet.h"

#include <linux/icmp.h>
#include <net/route.h>

#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/types.h"
#include "nat64/mod/icmp_wrapper.h"


#define MIN_IPV6_HDR_LEN sizeof(struct ipv6hdr)
#define MIN_IPV4_HDR_LEN sizeof(struct iphdr)
#define MIN_TCP_HDR_LEN sizeof(struct tcphdr)
#define MIN_UDP_HDR_LEN sizeof(struct udphdr)
#define MIN_ICMP6_HDR_LEN sizeof(struct icmp6hdr)
#define MIN_ICMP4_HDR_LEN sizeof(struct icmphdr)


void kfree_skb_queued(struct sk_buff *skb)
{
	struct sk_buff *next_skb;
	while (skb) {
		next_skb = skb->next;
		skb->next = skb->prev = NULL;
		kfree_skb(skb);
		skb = next_skb;
	}
}

int validate_lengths_tcp(unsigned int len, u16 l3_hdr_len, struct tcphdr *hdr)
{
	if (len < l3_hdr_len + MIN_TCP_HDR_LEN) {
		log_debug("Packet is too small to contain a basic TCP header.");
		return -EINVAL;
	}

	if (len < l3_hdr_len + tcp_hdr_len(hdr)) {
		log_debug("Packet is too small to contain its TCP header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_udp(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_UDP_HDR_LEN) {
		log_debug("Packet is too small to contain a UDP header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_icmp6(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP6_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv6 header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_icmp4(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP4_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv4 header.");
		return -EINVAL;
	}

	return 0;
}

int validate_ipv6_integrity(struct ipv6hdr *hdr, unsigned int len, bool is_truncated,
		struct hdr_iterator *iterator)
{
	enum hdr_iterator_result result;

	if (len < MIN_IPV6_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IPv6 header.");
		return -EINVAL;
	}
	if (!is_truncated && len != MIN_IPV6_HDR_LEN + be16_to_cpu(hdr->payload_len)) {
		log_debug("The packet's length does not match the IPv6 header's payload length field.");
		return -EINVAL;
	}

	hdr_iterator_init(iterator, hdr);
	result = hdr_iterator_last(iterator);

	switch (result) {
	case HDR_ITERATOR_SUCCESS:
		WARN(true, "Iterator reports there are headers beyond the payload.");
		break;
	case HDR_ITERATOR_END:
		return 0;
	case HDR_ITERATOR_UNSUPPORTED:
		/* RFC 6146 section 5.1. */
		log_debug("Packet contains an Authentication or ESP header, "
				"which I'm not supposed to support.");
		break;
	case HDR_ITERATOR_OVERFLOW:
		log_debug("IPv6 extension header analysis ran past the end of the packet. "
				"Packet seems corrupted; ignoring.");
		break;
	}

	return -EINVAL;
}

int skb_init_cb_ipv6(struct sk_buff *skb)
{
	struct jool_cb *cb = skb_jcb(skb);
	struct hdr_iterator iterator;
	int error;

	error = validate_ipv6_integrity(ipv6_hdr(skb), skb->len, false, &iterator);
	if (error)
		return error;

	/*
	 * If you're comparing this to init_ipv4_cb(), keep in mind that ip6_route_input() is not
	 * exported for dynamic modules to use (and linux doesn't know a route to the NAT64 prefix
	 * anyway), so we have to test the shit out of kernel IPv6 functions which might dereference
	 * the dst_entries of the skbs.
	 * We already know of a bug in Linux 3.12 that does exactly that, see icmp_wrapper.c.
	 */

	cb->l3_proto = L3PROTO_IPV6;
	cb->original_skb = skb;
	skb_set_transport_header(skb, iterator.data - (void *) skb_network_header(skb));

	switch (iterator.hdr_type) {
	case NEXTHDR_TCP:
		error = validate_lengths_tcp(skb->len, skb_l3hdr_len(skb), tcp_hdr(skb));
		if (error)
			return error;

		cb->l4_proto = L4PROTO_TCP;
		cb->payload = iterator.data + tcp_hdrlen(skb);
		break;

	case NEXTHDR_UDP:
		error = validate_lengths_udp(skb->len, skb_l3hdr_len(skb));
		if (error)
			return error;

		cb->l4_proto = L4PROTO_UDP;
		cb->payload = iterator.data + sizeof(struct udphdr);
		break;

	case NEXTHDR_ICMP:
		error = validate_lengths_icmp6(skb->len, skb_l3hdr_len(skb));
		if (error)
			return error;

		cb->l4_proto = L4PROTO_ICMP;
		cb->payload = iterator.data + sizeof(struct icmp6hdr);
		break;

	default:
		log_debug("Unsupported layer 4 protocol: %d", iterator.hdr_type);
		icmp64_send(skb, ICMPERR_PORT_UNREACHABLE, 0);
		return -EINVAL;
	}

	return 0;
}

int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated)
{
	u16 ip4_hdr_len;

	if (len < MIN_IPV4_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IP header.");
		/* Even if we expect it to be truncated, this length is unacceptable. */
		return -EINVAL;
	}
	if (hdr->ihl < 5) {
		log_debug("Packet's IHL field is too small.");
		return -EINVAL;
	}
	if (ip_fast_csum((u8 *) hdr, hdr->ihl)) {
		log_debug("Packet's IPv4 checksum is incorrect.");
		return -EINVAL;
	}

	if (is_truncated)
		return 0;

	ip4_hdr_len = 4 * hdr->ihl;
	if (len < ip4_hdr_len) {
		log_debug("Packet is too small to contain the IP header + options.");
		return -EINVAL;
	}
	if (len != be16_to_cpu(hdr->tot_len)) {
		log_debug("The packet's length does not equal the IPv4 header's lengh field.");
		return -EINVAL;
	}

	return 0;
}

int skb_init_cb_ipv4(struct sk_buff *skb)
{
	struct jool_cb *cb = skb_jcb(skb);
	struct iphdr *hdr4 = ip_hdr(skb);
	int error;

	error = validate_ipv4_integrity(hdr4, skb->len, false);
	if (error)
		return error;

#ifndef UNIT_TESTING
	if (skb && skb_rtable(skb) == NULL) {
		/*
		 * Some kernel functions assume that the incoming packet is already routed.
		 * Because they seem to pop up where we least expect them, we'll just route every incoming
		 * packet, regardless of whether we end up calling one of those functions.
		 */

		error = ip_route_input(skb, hdr4->daddr, hdr4->saddr, hdr4->tos, skb->dev);
		if (error) {
			log_debug("ip_route_input failed: %d", error);
			return error;
		}
	}
#endif

	cb->l3_proto = L3PROTO_IPV4;
	cb->original_skb = skb;
	skb_set_transport_header(skb, 4 * hdr4->ihl);

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		error = validate_lengths_tcp(skb->len, skb_l3hdr_len(skb), tcp_hdr(skb));
		if (error)
			return error;

		cb->l4_proto = L4PROTO_TCP;
		cb->payload = skb_transport_header(skb) + tcp_hdrlen(skb);
		break;

	case IPPROTO_UDP:
		error = validate_lengths_udp(skb->len, skb_l3hdr_len(skb));
		if (error)
			return error;

		cb->l4_proto = L4PROTO_UDP;
		cb->payload = skb_transport_header(skb) + sizeof(struct udphdr);
		break;

	case IPPROTO_ICMP:
		error = validate_lengths_icmp4(skb->len, skb_l3hdr_len(skb));
		if (error)
			return error;

		cb->l4_proto = L4PROTO_ICMP;
		cb->payload = skb_transport_header(skb) + sizeof(struct icmphdr);
		break;

	default:
		log_debug("Unsupported layer 4 protocol: %d", hdr4->protocol);
		icmp64_send(skb, ICMPERR_PROTO_UNREACHABLE, 0);
		return -EINVAL;
	}

	return 0;
}

static char *nexthdr_to_string(__u8 nexthdr)
{
	switch (nexthdr) {
	case NEXTHDR_TCP:
		return "TCP";
	case NEXTHDR_UDP:
		return "UDP";
	case NEXTHDR_ICMP:
		return "ICMP";
	case NEXTHDR_FRAGMENT:
		return "Fragment";
	}

	return "Don't know";
}

static char *protocol_to_string(__u8 protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_ICMP:
		return "ICMP";
	}

	return "Don't know";
}

void skb_print(struct sk_buff *skb)
{
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag_header;
	struct iphdr *hdr4;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct in_addr addr4;

	if (!skb) {
		pr_debug("(null)\n");
		return;
	}

	log_info("Layer 3 proto:%s", l3proto_to_string(skb_l3_proto(skb)));
	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV6:
		hdr6 = ipv6_hdr(skb);
		pr_debug("		version: %u\n", hdr6->version);
		pr_debug("		traffic class: %u\n", (hdr6->priority << 4) | (hdr6->flow_lbl[0] >> 4));
		pr_debug("		flow label: %u\n", ((hdr6->flow_lbl[0] & 0xf) << 16)
				| (hdr6->flow_lbl[1] << 8)
				| hdr6->flow_lbl[0]);
		pr_debug("		payload length: %u\n", be16_to_cpu(hdr6->payload_len));
		pr_debug("		next header: %s\n", nexthdr_to_string(hdr6->nexthdr));
		pr_debug("		hop limit: %u\n", hdr6->hop_limit);
		pr_debug("		source address: %pI6c\n", &hdr6->saddr);
		pr_debug("		destination address: %pI6c\n", &hdr6->daddr);

		if (hdr6->nexthdr == NEXTHDR_FRAGMENT) {
			frag_header = (struct frag_hdr *) (hdr6 + 1);
			pr_debug("Fragment header:\n");
			pr_debug("		next header: %s\n", nexthdr_to_string(frag_header->nexthdr));
			pr_debug("		reserved: %u\n", frag_header->reserved);
			pr_debug("		fragment offset: %u\n", get_fragment_offset_ipv6(frag_header));
			pr_debug("		more fragments: %u\n", is_more_fragments_set_ipv6(frag_header));
			pr_debug("		identification: %u\n", be32_to_cpu(frag_header->identification));
		}
		break;

	case L3PROTO_IPV4:
		hdr4 = ip_hdr(skb);
		pr_debug("		version: %u\n", hdr4->version);
		pr_debug("		header length: %u\n", hdr4->ihl);
		pr_debug("		type of service: %u\n", hdr4->tos);
		pr_debug("		total length: %u\n", be16_to_cpu(hdr4->tot_len));
		pr_debug("		identification: %u\n", be16_to_cpu(hdr4->id));
		pr_debug("		more fragments: %u\n", is_more_fragments_set_ipv4(hdr4));
		pr_debug("		don't fragment: %u\n", is_dont_fragment_set(hdr4));
		pr_debug("		fragment offset: %u\n", get_fragment_offset_ipv4(hdr4));
		pr_debug("		time to live: %u\n", hdr4->ttl);
		pr_debug("		protocol: %s\n", protocol_to_string(hdr4->protocol));
		pr_debug("		checksum: %u\n", hdr4->check);
		addr4.s_addr = hdr4->saddr;
		pr_debug("		source address: %pI4\n", &addr4);
		addr4.s_addr = hdr4->daddr;
		pr_debug("		destination address: %pI4\n", &addr4);
		break;
	}

	pr_debug("Layer 4 proto:%s\n", l4proto_to_string(skb_l4_proto(skb)));
	switch (skb_l4_proto(skb)) {
	case L4PROTO_TCP:
		tcp_header = tcp_hdr(skb);
		pr_debug("		source port: %u\n", be16_to_cpu(tcp_header->source));
		pr_debug("		destination port: %u\n", be16_to_cpu(tcp_header->dest));
		pr_debug("		seq: %u\n", be32_to_cpu(tcp_header->seq));
		pr_debug("		ack_seq: %u\n", be32_to_cpu(tcp_header->ack_seq));
		pr_debug("		doff:%u res1:%u cwr:%u ece:%u urg:%u\n", tcp_header->doff, tcp_header->res1,
				tcp_header->cwr, tcp_header->ece, tcp_header->urg);
		pr_debug("		ack:%u psh:%u rst:%u syn:%u fin:%u\n", tcp_header->ack, tcp_header->psh,
				tcp_header->rst, tcp_header->syn, tcp_header->fin);
		pr_debug("		window: %u\n", be16_to_cpu(tcp_header->window));
		pr_debug("		check: %u\n", tcp_header->check);
		pr_debug("		urg_ptr: %u\n", be16_to_cpu(tcp_header->urg_ptr));
		break;

	case L4PROTO_UDP:
		udp_header = udp_hdr(skb);
		pr_debug("		source port: %u\n", be16_to_cpu(udp_header->source));
		pr_debug("		destination port: %u\n", be16_to_cpu(udp_header->dest));
		pr_debug("		length: %u\n", be16_to_cpu(udp_header->len));
		pr_debug("		checksum: %u\n", udp_header->check);
		break;

	case L4PROTO_ICMP:
		/* too lazy */
		break;
	}
}

/**
 * Assumes that "pkt" is IPv4 and UDP, and ensures the UDP header's checksum field is set.
 * This has to be done because the field is mandatory only in IPv6, so Jool has to make up for lazy
 * IPv4 nodes.
 */
static int compute_csum_udp(struct sk_buff *skb)
{
	struct iphdr *hdr4;
	struct udphdr *hdr_udp;
	unsigned int datagram_len;

	hdr_udp = udp_hdr(skb);
	if (hdr_udp->check != 0)
		return 0; /* The client went through the trouble of computing the csum. */

	hdr4 = ip_hdr(skb);
	datagram_len = skb_l4hdr_len(skb) + skb_payload_len(skb);
	hdr_udp->check = csum_tcpudp_magic(hdr4->saddr, hdr4->daddr, datagram_len, IPPROTO_UDP,
			csum_partial(hdr_udp, datagram_len, 0));

	return 0;
}

/**
 * Assumes that pkt is a IPv6 ICMP message, and ensures that its checksum is valid, but only if it's
 * neccesary. See validate_csum_icmp4() for more info.
 */
static int validate_csum_icmp6(struct sk_buff *skb)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);
	struct icmp6hdr *hdr_icmp6 = icmp6_hdr(skb);
	unsigned int datagram_len;
	__sum16 tmp;
	__sum16 computed_csum;

	if (!is_icmp6_error(hdr_icmp6->icmp6_type))
		return 0;

	tmp = hdr_icmp6->icmp6_cksum;
	hdr_icmp6->icmp6_cksum = 0;
	datagram_len = skb_l4hdr_len(skb) + skb_payload_len(skb);
	computed_csum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr, datagram_len, NEXTHDR_ICMP,
			csum_partial(hdr_icmp6, datagram_len, 0));
	hdr_icmp6->icmp6_cksum = tmp;

	if (tmp != computed_csum) {
		log_debug("Checksum doesn't match. Expected: %x, actual: %x.", computed_csum, tmp);
		return -EINVAL;
	}

	return 0;
}

/**
 * Assumes that pkt is a IPv4 ICMP message, and ensures that its checksum is valid, but only if it's
 * neccesary. See the comments inside for more info.
 */
static int validate_csum_icmp4(struct sk_buff *skb)
{
	struct icmphdr *hdr = icmp_hdr(skb);
	__sum16 tmp;
	__sum16 computed_csum;

	if (!is_icmp4_error(hdr->type)) {
		/*
		 * The ICMP payload is not another packet.
		 * Hence, it will not be translated (it will be copied as-is).
		 * Hence, we will not have to recompute the checksum from scratch
		 * (we'll just update the old checksum with the new header's data).
		 * Hence, we don't have to validate the incoming checksum.
		 * (Because that will be the IPv6 node's responsibility.)
		 */
		return 0;
	}

	tmp = hdr->checksum;
	hdr->checksum = 0;
	computed_csum = ip_compute_csum(hdr, skb_l4hdr_len(skb) + skb_payload_len(skb));
	hdr->checksum = tmp;

	if (tmp != computed_csum) {
		log_debug("Checksum doesn't match. Expected: %x, actual: %x.", computed_csum, tmp);
		return -EINVAL;
	}

	return 0;
}

int fix_checksums_ipv6(struct sk_buff *skb) {
	int error = 0;

	switch (skb_l4_proto(skb)) {
	case L4PROTO_TCP:
	case L4PROTO_UDP:
		/* Nothing to do here. */
		break;

	case L4PROTO_ICMP:
		error = validate_csum_icmp6(skb);
		break;
	}

	return error;
}

int fix_checksums_ipv4(struct sk_buff *skb) {
	int error = 0;

	switch (skb_l4_proto(skb)) {
	case L4PROTO_TCP:
		/* Nothing to do here. */
		break;
	case L4PROTO_UDP:
		error = compute_csum_udp(skb);
		break;

	case L4PROTO_ICMP:
		error = validate_csum_icmp4(skb);
		break;
	}

	return error;
}
