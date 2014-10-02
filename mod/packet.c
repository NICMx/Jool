#include "nat64/mod/packet.h"

#include <linux/icmp.h>
#include <net/route.h>

#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/types.h"
#include "nat64/mod/icmp_wrapper.h"
#include "nat64/mod/stats.h"


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

int skb_aggregate_ipv4_payload_len(struct sk_buff *skb, unsigned int *len)
{
	struct iphdr *hdr;

	do {
		hdr = ip_hdr(skb);

		if (!is_more_fragments_set_ipv4(hdr)) {
			*len = get_fragment_offset_ipv4(hdr) + skb_l4hdr_len(skb) + skb_payload_len(skb);
			return 0;
		}

		skb = skb->next;
	} while (skb);

	WARN(true, "I'm missing the MF=false fragment...");
	return -EINVAL;
}

int skb_aggregate_ipv6_payload_len(struct sk_buff *skb, unsigned int *len)
{
	struct frag_hdr *hdr = skb_frag_hdr(skb);

	if (!hdr) {
		*len = skb_l4hdr_len(skb) + skb_payload_len(skb);
		return 0;
	}

	do {
		hdr = skb_frag_hdr(skb);

		if (!is_more_fragments_set_ipv6(hdr)) {
			*len = get_fragment_offset_ipv6(hdr) + skb_l4hdr_len(skb) + skb_payload_len(skb);
			return 0;
		}

		skb = skb->next;
	} while (skb);

	WARN(true, "I'm missing the MF=false fragment...");
	return -EINVAL;
}

int validate_lengths_tcp(unsigned int len, unsigned int l3_hdr_len, struct tcphdr *hdr)
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

int validate_lengths_udp(unsigned int len, unsigned int l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_UDP_HDR_LEN) {
		log_debug("Packet is too small to contain a UDP header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_icmp6(unsigned int len, unsigned int l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP6_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv6 header.");
		return -EINVAL;
	}

	return 0;
}

int validate_lengths_icmp4(unsigned int len, unsigned int l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP4_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv4 header.");
		return -EINVAL;
	}

	return 0;
}

int validate_ipv6_integrity(struct ipv6hdr *hdr, unsigned int len, bool is_truncated,
		struct hdr_iterator *iterator, int *field)
{
	enum hdr_iterator_result result;

	if (len < MIN_IPV6_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IPv6 header.");
		*field = IPSTATS_MIB_INTRUNCATEDPKTS;
		return -EINVAL;
	}
	if (!is_truncated && len != MIN_IPV6_HDR_LEN + be16_to_cpu(hdr->payload_len)) {
		log_debug("The packet's length does not match the IPv6 header's payload length field.");
		*field = IPSTATS_MIB_INHDRERRORS;
		return -EINVAL;
	}

	if (is_truncated)
		hdr_iterator_init_truncated(iterator, hdr, len);
	else
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

	/* If fall through here, indicates there is a Header Error. */
	*field = IPSTATS_MIB_INHDRERRORS;
	return -EINVAL;
}

bool icmp4_has_inner_packet(__u8 icmp_type)
{
	return is_icmp4_error(icmp_type);
}

bool icmpv6_has_inner_packet(__u8 icmp6_type)
{
	return is_icmp6_error(icmp6_type);
}

static int validate_inner_packet6(struct ipv6hdr *hdr6, unsigned int len, int *field)
{
	struct hdr_iterator iterator;
	struct icmp6hdr *l4_hdr;
	unsigned int l3_hdr_len;
	int error;

	log_debug("Validating inner packet 6");

	error = validate_ipv6_integrity(hdr6, len, true, &iterator, field);
	if (error)
		return error;

	l3_hdr_len = iterator.data - (void *) hdr6;

	switch (iterator.hdr_type) {
	case NEXTHDR_TCP:
		if (len < l3_hdr_len + MIN_TCP_HDR_LEN) {
			log_debug("Inner packet is too small to contain a basic TCP header.");
			*field = IPSTATS_MIB_INTRUNCATEDPKTS;
			return -EINVAL;
		}
		break;
	case NEXTHDR_UDP:
		error = validate_lengths_udp(len, l3_hdr_len);
		if (error) {
			*field = IPSTATS_MIB_INTRUNCATEDPKTS;
			return error;
		}
		break;
	case NEXTHDR_ICMP:
		error = validate_lengths_icmp6(len, l3_hdr_len);
		if (error) {
			*field = IPSTATS_MIB_INTRUNCATEDPKTS;
			return error;
		}
		l4_hdr = iterator.data;
		if (icmpv6_has_inner_packet(l4_hdr->icmp6_type)) {
			*field = IPSTATS_MIB_INHDRERRORS;
			return -EINVAL; /* packet inside packet inside packet. */
		}

		break;
	default:
		/*
		 * Why are we validating an error packet of a packet we couldn't have translated?
		 * Either an attack or shouldn't happen, so drop silently.
		 */
		*field = IPSTATS_MIB_INUNKNOWNPROTOS;
		return -EINVAL;
	}

	return 0;
}

int skb_init_cb_ipv6(struct sk_buff *skb)
{
	struct jool_cb *cb = skb_jcb(skb);
	struct hdr_iterator iterator;
	int error;
	int field = 0;

	error = validate_ipv6_integrity(ipv6_hdr(skb), skb->len, false, &iterator, &field);
	if (error) {
		inc_stats(skb, field);
		return error;
	}

	/*
	 * If you're comparing this to init_ipv4_cb(), keep in mind that ip6_route_input() is not
	 * exported for dynamic modules to use (and linux doesn't know a route to the NAT64 prefix
	 * anyway), so we have to test the shit out of kernel IPv6 functions which might dereference
	 * the dst_entries of the skbs.
	 * We already know of a bug in Linux 3.12 that does exactly that, see icmp_wrapper.c.
	 */

	cb->l3_proto = L3PROTO_IPV6;
	cb->frag_hdr = get_extension_header(ipv6_hdr(skb), NEXTHDR_FRAGMENT);
	cb->original_skb = skb;
	skb_set_transport_header(skb, iterator.data - (void *) skb_network_header(skb));
	cb->payload = iterator.data;

	switch (iterator.hdr_type) {
	case NEXTHDR_TCP:
		cb->l4_proto = L4PROTO_TCP;

		if (is_first_fragment_ipv6(cb->frag_hdr)) {
			error = validate_lengths_tcp(skb->len, skb_l3hdr_len(skb), tcp_hdr(skb));
			if (error) {
				inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
				return error;
			}
			cb->payload += tcp_hdrlen(skb);
		}
		break;

	case NEXTHDR_UDP:
		cb->l4_proto = L4PROTO_UDP;

		if (is_first_fragment_ipv6(cb->frag_hdr)) {
			error = validate_lengths_udp(skb->len, skb_l3hdr_len(skb));
			if (error) {
				inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
				return error;
			}
			cb->payload += sizeof(struct udphdr);
		}
		break;

	case NEXTHDR_ICMP:
		cb->l4_proto = L4PROTO_ICMP;

		if (is_first_fragment_ipv6(cb->frag_hdr)) {
			error = validate_lengths_icmp6(skb->len, skb_l3hdr_len(skb));
			if (error) {
				inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
				return error;
			}
			cb->payload += sizeof(struct icmp6hdr);

			if (icmpv6_has_inner_packet(icmp6_hdr(skb)->icmp6_type)) {
				error = validate_inner_packet6(cb->payload, skb_payload_len(skb), &field);
				if (error) {
					inc_stats(skb, field);
					return error;
				}
			}
		}
		break;

	default:
		log_debug("Unsupported layer 4 protocol: %d", iterator.hdr_type);
		icmp64_send(skb, ICMPERR_PORT_UNREACHABLE, 0);
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}


	return 0;
}

int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated, int *field)
{
	if (len < MIN_IPV4_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IP header.");
		*field = IPSTATS_MIB_INTRUNCATEDPKTS;
		return -EINVAL;
	}
	if (hdr->ihl < 5) {
		log_debug("Packet's IHL field is too small.");
		*field = IPSTATS_MIB_INHDRERRORS;
		return -EINVAL;
	}
	if (ip_fast_csum((u8 *) hdr, hdr->ihl)) {
		log_debug("Packet's IPv4 checksum is incorrect.");
		*field = IPSTATS_MIB_INHDRERRORS;
		return -EINVAL;
	}
	if (len < 4 * hdr->ihl) {
		log_debug("Packet is too small to contain the IP header + options.");
		*field = IPSTATS_MIB_INTRUNCATEDPKTS;
		return -EINVAL;
	}

	if (is_truncated)
		return 0;

	if (len != be16_to_cpu(hdr->tot_len)) {
		log_debug("The packet's length does not equal the IPv4 header's lengh field.");
		*field = IPSTATS_MIB_INHDRERRORS;
		return -EINVAL;
	}

	return 0;
}

static int validate_inner_packet4(struct iphdr *hdr4, unsigned int len, int *field)
{
	struct icmphdr *l4_hdr;
	unsigned int l3_hdr_len;
	int error;

	log_debug("Validating inner packet 4");

	error = validate_ipv4_integrity(hdr4, len, true, field);
	if (error)
		return error;

	l3_hdr_len = 4 * hdr4->ihl;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		if (len < l3_hdr_len + MIN_TCP_HDR_LEN) {
			log_debug("Inner packet is too small to contain a basic TCP header.");
			*field = IPSTATS_MIB_INTRUNCATEDPKTS;
			return -EINVAL;
		}

		break;
	case IPPROTO_UDP:
		error = validate_lengths_udp(len, l3_hdr_len);
		if (error) {
			*field = IPSTATS_MIB_INTRUNCATEDPKTS;
			return error;
		}

		break;
	case IPPROTO_ICMP:
		error = validate_lengths_icmp4(len, l3_hdr_len);
		if (error) {
			*field = IPSTATS_MIB_INTRUNCATEDPKTS;
			return error;
		}
		l4_hdr = ((void *) hdr4) + l3_hdr_len;
		if (icmp4_has_inner_packet(l4_hdr->type)) {
			*field = IPSTATS_MIB_INHDRERRORS;
			return -EINVAL; /* packet inside packet inside packet. */
		}

		break;
	default:
		/*
		 * Why are we validating an error packet of a packet we couldn't have translated?
		 * Either an attack or shouldn't happen, so drop silently.
		 */
		*field = IPSTATS_MIB_INUNKNOWNPROTOS;
		return -EINVAL;
	}

	return 0;
}

int skb_init_cb_ipv4(struct sk_buff *skb)
{
	struct jool_cb *cb = skb_jcb(skb);
	struct iphdr *hdr4 = ip_hdr(skb);
	int error;
	int field = 0;

	error = validate_ipv4_integrity(hdr4, skb->len, false, &field);
	if (error) {
		inc_stats(skb, field);
		return error;
	}

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
			inc_stats(skb, IPSTATS_MIB_INNOROUTES);
			return error;
		}
	}
#endif

	cb->l3_proto = L3PROTO_IPV4;
	cb->frag_hdr = NULL;
	cb->original_skb = skb;
	skb_set_transport_header(skb, 4 * hdr4->ihl);
	cb->payload = skb_transport_header(skb);

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		cb->l4_proto = L4PROTO_TCP;

		if (is_first_fragment_ipv4(hdr4)) {
			error = validate_lengths_tcp(skb->len, skb_l3hdr_len(skb), tcp_hdr(skb));
			if (error) {
				inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
				return error;
			}
			cb->payload += tcp_hdrlen(skb);
		}
		break;

	case IPPROTO_UDP:
		cb->l4_proto = L4PROTO_UDP;

		if (is_first_fragment_ipv4(hdr4)) {
			error = validate_lengths_udp(skb->len, skb_l3hdr_len(skb));
			if (error) {
				inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
				return error;
			}
			cb->payload += sizeof(struct udphdr);
		}
		break;

	case IPPROTO_ICMP:
		cb->l4_proto = L4PROTO_ICMP;

		if (is_first_fragment_ipv4(hdr4)) {
			error = validate_lengths_icmp4(skb->len, skb_l3hdr_len(skb));
			if (error) {
				inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
				return error;
			}
			cb->payload += sizeof(struct icmphdr);

			if (icmp4_has_inner_packet(icmp_hdr(skb)->type)) {
				error = validate_inner_packet4(cb->payload, skb_payload_len(skb), &field);
				if (error) {
					inc_stats(skb, field);
					return error;
				}
			}
		}
		break;

	default:
		log_debug("Unsupported layer 4 protocol: %d", hdr4->protocol);
		icmp64_send(skb, ICMPERR_PROTO_UNREACHABLE, 0);
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
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

static void print_l4_hdr(struct sk_buff *skb)
{
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct icmphdr *icmp_header;

	pr_debug("Layer 4 proto: %s\n", l4proto_to_string(skb_l4_proto(skb)));
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
		pr_debug("		check: %x\n", be16_to_cpu((__force __be16) tcp_header->check));
		pr_debug("		urg_ptr: %u\n", be16_to_cpu(tcp_header->urg_ptr));
		break;

	case L4PROTO_UDP:
		udp_header = udp_hdr(skb);
		pr_debug("		source port: %u\n", be16_to_cpu(udp_header->source));
		pr_debug("		destination port: %u\n", be16_to_cpu(udp_header->dest));
		pr_debug("		length: %u\n", be16_to_cpu(udp_header->len));
		pr_debug("		checksum: %x\n", be16_to_cpu((__force __be16) udp_header->check));
		break;

	case L4PROTO_ICMP:
		icmp_header = icmp_hdr(skb);
		pr_debug("		type: %u", icmp_header->type);
		pr_debug("		code: %u", icmp_header->code);
		pr_debug("		checksum: %x\n", be16_to_cpu((__force __be16) icmp_header->checksum));
		pr_debug("		un: %x", be32_to_cpu(icmp_header->un.gateway));
		break;
	}
}

void skb_print(struct sk_buff *skb)
{
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag_header;
	struct iphdr *hdr4;
	struct in_addr addr4;
	u16 frag_offset = 0;
	unsigned char *payload;
	unsigned int x;

	pr_debug("----------------\n");

	if (!skb) {
		pr_debug("(null)\n");
		return;
	}

	pr_debug("Layer 3 proto: %s", l3proto_to_string(skb_l3_proto(skb)));
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
			frag_offset = get_fragment_offset_ipv6(frag_header);
		}
		break;

	case L3PROTO_IPV4:
		hdr4 = ip_hdr(skb);
		pr_debug("		version: %u\n", hdr4->version);
		pr_debug("		header length: %u\n", hdr4->ihl);
		pr_debug("		type of service: %u\n", hdr4->tos);
		pr_debug("		total length: %u\n", be16_to_cpu(hdr4->tot_len));
		pr_debug("		identification: %u\n", be16_to_cpu(hdr4->id));
		pr_debug("		don't fragment: %u\n", is_dont_fragment_set(hdr4));
		pr_debug("		more fragments: %u\n", is_more_fragments_set_ipv4(hdr4));
		pr_debug("		fragment offset: %u\n", get_fragment_offset_ipv4(hdr4));
		pr_debug("		time to live: %u\n", hdr4->ttl);
		pr_debug("		protocol: %s\n", protocol_to_string(hdr4->protocol));
		pr_debug("		checksum: %x\n", be16_to_cpu((__force __be16) hdr4->check));
		addr4.s_addr = hdr4->saddr;
		pr_debug("		source address: %pI4\n", &addr4);
		addr4.s_addr = hdr4->daddr;
		pr_debug("		destination address: %pI4\n", &addr4);
		frag_offset = get_fragment_offset_ipv4(hdr4);
		break;
	}

	if (frag_offset == 0)
		print_l4_hdr(skb);

	pr_debug("Payload (length %u):\n", skb_payload_len(skb));
	payload = skb_payload(skb);
	if (skb_payload_len(skb))
		printk("		%u", payload[0]);
	for (x = 1; x < skb_payload_len(skb); x++) {
		if (x%12)
			printk(", %u", payload[x]);
		else
			printk("\n		%u", payload[x]);
	}
	printk("\n");
}

int validate_icmp6_csum(struct sk_buff *skb) {
	struct ipv6hdr *ip6_hdr;
	struct icmp6hdr *hdr_icmp6;
	unsigned int datagram_len;
	__sum16 csum;

	if (skb_l4_proto(skb) != L4PROTO_ICMP)
		return 0;

	hdr_icmp6 = icmp6_hdr(skb);
	if (!is_icmp6_error(hdr_icmp6->icmp6_type))
		return 0;

	ip6_hdr = ipv6_hdr(skb);
	datagram_len = skb_l4hdr_len(skb) + skb_payload_len(skb);
	csum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr, datagram_len, NEXTHDR_ICMP,
			csum_partial(hdr_icmp6, datagram_len, 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return -EINVAL;
	}

	return 0;
}

int validate_icmp4_csum(struct sk_buff *skb) {
	struct icmphdr *hdr;
	__sum16 csum;

	if (skb_l4_proto(skb) != L4PROTO_ICMP)
		return 0;

	hdr = icmp_hdr(skb);
	if (!is_icmp4_error(hdr->type))
		return 0;

	csum = ip_compute_csum(hdr, skb_l4hdr_len(skb) + skb_payload_len(skb));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return -EINVAL;
	}

	return 0;
}
