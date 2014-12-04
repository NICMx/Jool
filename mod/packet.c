#include "nat64/mod/packet.h"

#include <linux/version.h>
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


/* TODO (issue #41) review callers. */
void kfree_skb_queued(struct sk_buff *skb)
{
	kfree_skb(skb);
}

bool icmp4_has_inner_packet(__u8 icmp_type)
{
	return is_icmp4_error(icmp_type);
}

bool icmp6_has_inner_packet(__u8 icmp6_type)
{
	return is_icmp6_error(icmp6_type);
}

static int init_l4(struct sk_buff *skb, u8 protocol, bool is_first_fragment)
{
	struct jool_cb *cb = skb_jcb(skb);
	int error = 0;

	cb->payload = skb_transport_header(skb);

	switch (protocol) {
	case IPPROTO_TCP:
		cb->l4_proto = L4PROTO_TCP;
		if (is_first_fragment) {
			if (!pskb_may_pull(skb, skb_l3hdr_len(skb) + sizeof(struct tcphdr)))
				goto truncated;
			if (!pskb_may_pull(skb, skb_l3hdr_len(skb) + tcp_hdrlen(skb)))
				goto truncated;
			cb->payload += tcp_hdrlen(skb);
		}
		break;

	case IPPROTO_UDP:
		cb->l4_proto = L4PROTO_UDP;
		if (is_first_fragment) {
			if (!pskb_may_pull(skb, skb_l3hdr_len(skb) + sizeof(struct udphdr)))
				goto truncated;
			cb->payload += sizeof(struct udphdr);
		}
		break;

	case IPPROTO_ICMP:
	case NEXTHDR_ICMP:
		cb->l4_proto = L4PROTO_ICMP;
		if (is_first_fragment){
			if (!pskb_may_pull(skb, skb_l3hdr_len(skb) + sizeof(struct icmphdr)))
				goto truncated;
			cb->payload += sizeof(struct icmphdr);
		}
		break;

	default:
		log_debug("Unsupported layer 4 protocol: %d", protocol);
		icmp64_send(skb, ICMPERR_PROTO_UNREACHABLE, 0);
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}

	return error;

truncated:
	log_debug("Packet is too small to contain its layer-4 header.");
	inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return -EINVAL;
}

int init_l4_inner(struct sk_buff *skb, u8 protocol, unsigned int offset)
{
	switch (protocol) {
	case IPPROTO_TCP:
		if (!pskb_may_pull(skb, offset + sizeof(struct tcphdr))) {
			log_debug("Inner packet is too small to contain a basic TCP header.");
			return -EINVAL;
		}
		break;

	case IPPROTO_UDP:
		if (!pskb_may_pull(skb, offset + sizeof(struct udphdr))) {
			log_debug("Inner packet is too small to contain a UDP header.");
			return -EINVAL;
		}
		break;

	case IPPROTO_ICMP:
	case NEXTHDR_ICMP:
		if (!pskb_may_pull(skb, offset + sizeof(struct icmphdr))) {
			log_debug("Inner packet is too small to contain a ICMP header.");
			return -EINVAL;
		}
		break;

	default:
		/*
		 * Why are we validating an error packet of a packet we couldn't have translated?
		 * Either an attack or shouldn't happen, so drop silently.
		 */
//		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}

	return 0;
}

/**
 * Warning: Result is an inverted boolean. Zero means "no problem", nonzero is an error code and
 * therefore means "no".
 */
static int may_pull_ipv6_hdrs(struct sk_buff *skb)
{
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;
	int offset;
	bool result;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	offset = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr);
#else
	__be16 frag_offset;
	offset = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr, &frag_offset);
#endif

	if (offset == -1) {
		log_debug("ipv6_skip_exthdr() returned -1.");
		return -EINVAL;
	}

	result = pskb_may_pull(skb, offset);
	if (!result) {
		log_debug("Could not 'pull' the extension IPv6 headers out of the skb.");
		return -EINVAL;
	}

	return 0;
}

static int iterate_till_end(struct hdr_iterator *iterator, struct frag_hdr **fhdr)
{
	enum hdr_iterator_result result;

	*fhdr = NULL;
	do {
		if (iterator->hdr_type == NEXTHDR_FRAGMENT)
			*fhdr = iterator->data;
	} while ((result = hdr_iterator_next(iterator)) == HDR_ITERATOR_SUCCESS);

	switch (result) {
	case HDR_ITERATOR_END:
		break;
	case HDR_ITERATOR_UNSUPPORTED:
		/* RFC 6146 section 5.1. */
		log_debug("Packet contains an Auth or ESP header, which I'm not supposed to support.");
		return -EINVAL;
	case HDR_ITERATOR_OVERFLOW:
		WARN(true, "Iterator overflowed despite ipv6_skip_exthdr()'s success.");
		return -EINVAL;
	case HDR_ITERATOR_SUCCESS:
		WARN(true, "Iteration ended nonsensically.");
		return -EINVAL;
	}

	return 0;
}

static int init_inner_packet6(struct sk_buff *skb)
{
	struct ipv6hdr *hdr6 = skb_jcb(skb)->payload;
	struct frag_hdr *fhdr;
	struct icmp6hdr *l4_hdr;
	struct hdr_iterator iterator;
	unsigned int offset = skb_l3hdr_len(skb) + sizeof(struct icmphdr);
	int error;

	log_debug("Validating inner IPv6 packet.");

	if (!pskb_may_pull(skb, offset + sizeof(struct ipv6hdr)))
		return -EINVAL;
	if (unlikely(hdr6->version != 6))
		return -EINVAL;
	error = may_pull_ipv6_hdrs(skb);
	if (error)
		return error;

	hdr_iterator_init_truncated(&iterator, hdr6, skb_headlen(skb) - offset);
	error = iterate_till_end(&iterator, &fhdr);
	if (error)
		return error;

	if (!is_first_fragment_ipv6(fhdr)) {
		log_debug("Inner packet is not a first fragment...");
		return -EINVAL;
	}

	error = init_l4_inner(skb, iterator.hdr_type, iterator.data - (void *) ipv6_hdr(skb));
	if (error)
		return error;

	if (iterator.hdr_type == L4PROTO_ICMP) {
		l4_hdr = iterator.data;
		if (icmp6_has_inner_packet(l4_hdr->icmp6_type)) {
			log_debug("Packet inside packet inside packet.");
			return -EINVAL; /* packet inside packet inside packet. */
		}
	}

	return 0;
}

/*
 * TODO (issue #41) review stats.
 */
int skb_init_cb_ipv6(struct sk_buff *skb)
{
	struct jool_cb *cb = skb_jcb(skb);
	struct frag_hdr *fragment_hdr;
	struct hdr_iterator iterator;
	int error;

#ifdef BENCHMARK
	getnstimeofday(&cb->start_time);
#endif

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return -EINVAL;
	if (skb->len != sizeof(struct ipv6hdr) + ntohs(ipv6_hdr(skb)->payload_len))
		return -EINVAL;
	error = may_pull_ipv6_hdrs(skb);
	if (error)
		return error;

	hdr_iterator_init_truncated(&iterator, ipv6_hdr(skb), skb_headlen(skb));
	error = iterate_till_end(&iterator, &fragment_hdr);
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
	cb->is_inner = 0;
	cb->original_skb = skb;
	skb_set_transport_header(skb, iterator.data - (void *) skb_network_header(skb));

	error = init_l4(skb, iterator.hdr_type, is_first_fragment_ipv6(fragment_hdr));
	if (error)
		return error;

	if (cb->l4_proto == L4PROTO_ICMP && icmp6_has_inner_packet(icmp6_hdr(skb)->icmp6_type))
		error = init_inner_packet6(skb);

	return error;
}

static int init_inner_packet4(struct sk_buff *skb)
{
	struct iphdr *hdr4 = skb_jcb(skb)->payload;
	struct icmphdr *l4_hdr;
	unsigned int l3_hdr_len;
	unsigned int offset = skb_l3hdr_len(skb) + sizeof(struct icmphdr);
	int error;

	log_debug("Validating IPv4 inner packet.");

	if (!pskb_may_pull(skb, offset + sizeof(struct iphdr))) {
		log_debug("Inner packet is too small to contain a basic IPv4 header.");
		goto mem_err;
	}
	if (unlikely(hdr4->version != 4)) {
		log_debug("Inner packet is not IPv4.");
		goto in_err;
	}
	if (unlikely(hdr4->ihl < 5)) {
		log_debug("Inner packet's IHL is bogus.");
		goto in_err;
	}

	l3_hdr_len = 4 * hdr4->ihl;

	if (!pskb_may_pull(skb, l3_hdr_len)) {
		log_debug("Inner packet is too small to contain its IPv4 header.");
		goto mem_err;
	}
	if (unlikely(ip_fast_csum((u8 *) hdr4, hdr4->ihl))) {
		log_debug("Inner packet's header checksum doesn't match.");
		goto in_err;
	}
	if (unlikely(ntohs(hdr4->tot_len) < l3_hdr_len)) {
		log_debug("Inner packet's total length is bogus.");
		goto in_err;
	}
	if (unlikely(!is_first_fragment_ipv4(hdr4))) {
		log_debug("Inner packet is not a first fragment...");
		goto in_err;
	}

	error = init_l4_inner(skb, hdr4->protocol, offset + l3_hdr_len);
	if (error)
		return error;

	if (hdr4->protocol == IPPROTO_ICMP) {
		l4_hdr = ((void *) hdr4) + l3_hdr_len;
		if (unlikely(icmp4_has_inner_packet(l4_hdr->type))) {
			log_debug("Packet inside packet inside packet.");
//			inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
			return -EINVAL;
		}
	}

	return 0;

mem_err:
	return -EINVAL;

in_err:
//	ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
	return -EINVAL;
}

/*
 * TODO (issue #41) how does pskb_may_pull() move the hdr pointers when sk_buff_data_t is a ptr?
 */
int skb_init_cb_ipv4(struct sk_buff *skb)
{
	struct jool_cb *cb = skb_jcb(skb);
	struct iphdr *hdr4 = ip_hdr(skb);
	int error;

#ifdef BENCHMARK
	getnstimeofday(&cb->start_time);
#endif

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
	cb->is_inner = 0;
	cb->original_skb = skb;
	skb_set_transport_header(skb, 4 * hdr4->ihl);

	error = init_l4(skb, hdr4->protocol, is_first_fragment_ipv4(hdr4));
	if (error)
		return error;

	if (cb->l4_proto == L4PROTO_ICMP && icmp4_has_inner_packet(icmp_hdr(skb)->type))
		error = init_inner_packet4(skb);

	return error;
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

	pr_debug("Payload (length %u):\n", skb_payload_len_frag(skb));
	payload = skb_payload(skb);
	if (skb_payload_len_frag(skb))
		printk("		%u", payload[0]);
	for (x = 1; x < skb_payload_len_frag(skb); x++) {
		if (x%12)
			printk(", %u", payload[x]);
		else
			printk("\n		%u", payload[x]);
	}
	printk("\n");
}

int validate_icmp6_csum(struct sk_buff *skb)
{
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
	datagram_len = skb_l3payload_len(skb);
	csum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr, datagram_len, NEXTHDR_ICMP,
			skb_checksum(skb, skb_transport_offset(skb), datagram_len, 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return -EINVAL;
	}

	return 0;
}

int validate_icmp4_csum(struct sk_buff *skb)
{
	struct icmphdr *hdr;
	__sum16 csum;

	if (skb_l4_proto(skb) != L4PROTO_ICMP)
		return 0;

	hdr = icmp_hdr(skb);
	if (!is_icmp4_error(hdr->type))
		return 0;

	csum = csum_fold(skb_checksum(skb, skb_transport_offset(skb), skb_l3payload_len(skb), 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return -EINVAL;
	}

	return 0;
}
