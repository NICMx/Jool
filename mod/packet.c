#include "nat64/mod/packet.h"

#include <linux/icmp.h>
#include <net/route.h>

#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
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
		log_warning("Packet is too small to contain a basic TCP header.");
		return -EINVAL;
	}

	if (len < l3_hdr_len + tcp_hdr_len(hdr)) {
		log_warning("Packet is too small to contain its TCP header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_udp(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_UDP_HDR_LEN) {
		log_warning("Packet is too small to contain a UDP header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_icmp6(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP6_HDR_LEN) {
		log_warning("Packet is too small to contain a ICMPv6 header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_icmp4(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP4_HDR_LEN) {
		log_warning("Packet is too small to contain a ICMPv4 header.");
		return -EINVAL;
	}

	return 0;
}

int validate_ipv6_integrity(struct ipv6hdr *hdr, unsigned int len, bool is_truncated,
		struct hdr_iterator *iterator)
{
	enum hdr_iterator_result result;

	if (len < MIN_IPV6_HDR_LEN) {
		log_warning("Packet is too small to contain a basic IPv6 header.");
		return -EINVAL;
	}
	if (!is_truncated && len != MIN_IPV6_HDR_LEN + be16_to_cpu(hdr->payload_len)) {
		log_warning("The packet's length does not match the IPv6 header's payload length field.");
		return -EINVAL;
	}

	hdr_iterator_init(iterator, hdr);
	result = hdr_iterator_last(iterator);

	switch (result) {
	case HDR_ITERATOR_SUCCESS:
		log_crit(ERR_INVALID_ITERATOR, "Iterator reports there are headers beyond the payload.");
		break;
	case HDR_ITERATOR_END:
		return 0;
	case HDR_ITERATOR_UNSUPPORTED:
		/* RFC 6146 section 5.1. */
		log_info("Packet contains an Authentication or ESP header, "
				"which I'm not supposed to support.");
		break;
	case HDR_ITERATOR_OVERFLOW:
		log_warning("IPv6 extension header analysis ran past the end of the packet. "
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
		log_info("Unsupported layer 4 protocol: %d", iterator.hdr_type);
		icmp64_send(skb, ICMPERR_PROTO_UNREACHABLE, 0);
		return -EINVAL;
	}

	return 0;
}

int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated)
{
	u16 ip4_hdr_len;

	if (len < MIN_IPV4_HDR_LEN) {
		log_warning("Packet is too small to contain a basic IP header.");
		return -EINVAL;
	}
	if (hdr->ihl < 5) {
		log_warning("Packet's IHL field is too small.");
		return -EINVAL;
	}
	if (ip_fast_csum((u8 *) hdr, hdr->ihl)) {
		log_warning("Packet's IPv4 checksum is incorrect.");
		return -EINVAL;
	}

	if (is_truncated)
		return 0;

	ip4_hdr_len = 4 * hdr->ihl;
	if (len < ip4_hdr_len) {
		log_warning("Packet is too small to contain the IP header + options.");
		return -EINVAL;
	}
	if (len != be16_to_cpu(hdr->tot_len)) {
		log_warning("The packet's length does not equal the IPv4 header's lengh field.");
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
			log_err(ERR_UNKNOWN_ERROR, "ip_route_input failed: %d", error);
			return error;
		}
		log_debug("making rtable %p", skb_rtable(skb));
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
		log_info("Unsupported layer 4 protocol: %d", hdr4->protocol);
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
		log_info("(null)");
		return;
	}

	log_info("Layer 3 proto:%s", l3proto_to_string(skb_l3_proto(skb)));
	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV6:
		hdr6 = ipv6_hdr(skb);
		log_info("		version: %u", hdr6->version);
		log_info("		traffic class: %u", (hdr6->priority << 4) | (hdr6->flow_lbl[0] >> 4));
		log_info("		flow label: %u", ((hdr6->flow_lbl[0] & 0xf) << 16) | (hdr6->flow_lbl[1] << 8) | hdr6->flow_lbl[0]);
		log_info("		payload length: %u", be16_to_cpu(hdr6->payload_len));
		log_info("		next header: %s", nexthdr_to_string(hdr6->nexthdr));
		log_info("		hop limit: %u", hdr6->hop_limit);
		log_info("		source address: %pI6c", &hdr6->saddr);
		log_info("		destination address: %pI6c", &hdr6->daddr);

		if (hdr6->nexthdr == NEXTHDR_FRAGMENT) {
			frag_header = (struct frag_hdr *) (hdr6 + 1);
			log_info("Fragment header:");
			log_info("		next header: %s", nexthdr_to_string(frag_header->nexthdr));
			log_info("		reserved: %u", frag_header->reserved);
			log_info("		fragment offset: %u", get_fragment_offset_ipv6(frag_header));
			log_info("		more fragments: %u", is_more_fragments_set_ipv6(frag_header));
			log_info("		identification: %u", be32_to_cpu(frag_header->identification));
		}
		break;

	case L3PROTO_IPV4:
		hdr4 = ip_hdr(skb);
		log_info("		version: %u", hdr4->version);
		log_info("		header length: %u", hdr4->ihl);
		log_info("		type of service: %u", hdr4->tos);
		log_info("		total length: %u", be16_to_cpu(hdr4->tot_len));
		log_info("		identification: %u", be16_to_cpu(hdr4->id));
		log_info("		more fragments: %u", is_more_fragments_set_ipv4(hdr4));
		log_info("		don't fragment: %u", is_dont_fragment_set(hdr4));
		log_info("		fragment offset: %u", get_fragment_offset_ipv4(hdr4));
		log_info("		time to live: %u", hdr4->ttl);
		log_info("		protocol: %s", protocol_to_string(hdr4->protocol));
		log_info("		checksum: %u", hdr4->check);
		addr4.s_addr = hdr4->saddr;
		log_info("		source address: %pI4", &addr4);
		addr4.s_addr = hdr4->daddr;
		log_info("		destination address: %pI4", &addr4);
		break;
	}

	log_info("Layer 4 proto:%s", l4proto_to_string(skb_l4_proto(skb)));
	switch (skb_l4_proto(skb)) {
	case L4PROTO_TCP:
		tcp_header = tcp_hdr(skb);
		log_info("		source port: %u", be16_to_cpu(tcp_header->source));
		log_info("		destination port: %u", be16_to_cpu(tcp_header->dest));
		log_info("		seq: %u", be32_to_cpu(tcp_header->seq));
		log_info("		ack_seq: %u", be32_to_cpu(tcp_header->ack_seq));
		log_info("		doff:%u res1:%u cwr:%u ece:%u urg:%u", tcp_header->doff, tcp_header->res1,
				tcp_header->cwr, tcp_header->ece, tcp_header->urg);
		log_info("		ack:%u psh:%u rst:%u syn:%u fin:%u", tcp_header->ack, tcp_header->psh,
				tcp_header->rst, tcp_header->syn, tcp_header->fin);
		log_info("		window: %u", be16_to_cpu(tcp_header->window));
		log_info("		check: %u", tcp_header->check);
		log_info("		urg_ptr: %u", be16_to_cpu(tcp_header->urg_ptr));
		break;

	case L4PROTO_UDP:
		udp_header = udp_hdr(skb);
		log_info("		source port: %u", be16_to_cpu(udp_header->source));
		log_info("		destination port: %u", be16_to_cpu(udp_header->dest));
		log_info("		length: %u", be16_to_cpu(udp_header->len));
		log_info("		checksum: %u", udp_header->check);
		break;

	case L4PROTO_ICMP:
		/* too lazy */
		break;
	case L4PROTO_NONE:
		break;
	}
}
