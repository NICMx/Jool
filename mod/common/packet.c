#include "nat64/mod/common/packet.h"

#include <linux/version.h>
#include <linux/icmp.h>
#include <net/route.h>

#include "nat64/comm/constants.h"
#include "nat64/comm/str_utils.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/stats.h"


#define MIN_IPV6_HDR_LEN sizeof(struct ipv6hdr)
#define MIN_IPV4_HDR_LEN sizeof(struct iphdr)
#define MIN_TCP_HDR_LEN sizeof(struct tcphdr)
#define MIN_UDP_HDR_LEN sizeof(struct udphdr)
#define MIN_ICMP6_HDR_LEN sizeof(struct icmp6hdr)
#define MIN_ICMP4_HDR_LEN sizeof(struct icmphdr)


static bool icmp4_has_inner_packet(__u8 icmp_type)
{
	return is_icmp4_error(icmp_type);
}

static bool icmp6_has_inner_packet(__u8 icmp6_type)
{
	return is_icmp6_error(icmp6_type);
}

/**
 * Apparently, as of 2007, Netfilter modules can assume they are the sole owners of their
 * skbs (http://lists.openwall.net/netdev/2007/10/14/13).
 * I can sort of confirm it by noticing that if it's not the case, editing the sk_buff
 * structs themselves would be overly cumbersome (since they'd have to operate on a clone,
 * and bouncing the clone back to Netfilter is kind of outside Netfilter's design).
 * This is relevant because we need to call pskb_may_pull(), which might eventually call
 * pskb_expand_head(), and that panics if the packet is shared.
 * Therefore, I think this validation (with messy WARN included) is fair.
 */
static int fail_if_shared(struct sk_buff *skb)
{
	if (WARN(skb_shared(skb), "The packet is shared!"))
		return -EINVAL;

	/*
	 * Keep in mind... "shared" and "cloned" are different concepts.
	 * We know the sk_buff struct is unique, but somebody else might have an active pointer towards
	 * the data area.
	 */
	return 0;
}

/**
 * "call pskb_may_pull(skb, len) then restore the pointers that maybe went kaboom."
 */
static bool may_pull_then_fix(struct sk_buff *skb, unsigned int len,
		int l4_offset, unsigned int l4hdr_len)
{
	if (!pskb_may_pull(skb, len))
		return false;

	skb_set_transport_header(skb, l4_offset);
	skb_jcb(skb)->payload = skb_transport_header(skb) + l4hdr_len;

	return true;
}

/**
 * "Call may_pull_then_fix(), assume we're pulling an outer layer 4 header."
 *
 * ("assume we're pulling an outer layer 4 header" can also be described as
 * "assume len is 'l4_offset + l4hdr_len' and 'l4_offset = skb_l3hdr_len(skb)'".)
 */
static bool may_pull_l4(struct sk_buff *skb, unsigned int l4hdr_len)
{
	unsigned int l3hdr_len = skb_l3hdr_len(skb);
	return may_pull_then_fix(skb, l3hdr_len + l4hdr_len, l3hdr_len, l4hdr_len);
}

/**
 * "Call may_pull_then_fix(), the new pointers should simply be adapted from the old packet's."
 */
static bool may_pull_keep(struct sk_buff *skb, unsigned int len)
{
	return may_pull_then_fix(skb, len, skb_l3hdr_len(skb), skb_l4hdr_len(skb));
}

static int init_l4(struct sk_buff *skb, __u8 protocol, bool is_first_fragment)
{
	struct jool_cb *cb = skb_jcb(skb);

	/* This default value will be kept if the packet is a fragment. */
	cb->payload = skb_transport_header(skb);

	switch (protocol) {
	case IPPROTO_TCP:
		cb->l4_proto = L4PROTO_TCP;
		if (is_first_fragment) {
			if (!may_pull_l4(skb, sizeof(struct tcphdr)))
				goto truncated;
			if (!may_pull_l4(skb, tcp_hdrlen(skb)))
				goto truncated;
		}
		break;

	case IPPROTO_UDP:
		cb->l4_proto = L4PROTO_UDP;
		if (is_first_fragment && !may_pull_l4(skb, sizeof(struct udphdr)))
			goto truncated;
		break;

	case IPPROTO_ICMP:
	case NEXTHDR_ICMP:
		cb->l4_proto = L4PROTO_ICMP;
		if (is_first_fragment && !may_pull_l4(skb, sizeof(struct icmphdr)))
			goto truncated;
		break;

	default:
		log_debug("Unsupported layer 4 protocol: %d", protocol);
		icmp64_send(skb, ICMPERR_PROTO_UNREACHABLE, 0);
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}

	return 0;

truncated:
	log_debug("Packet is too small to contain its layer-4 header (proto %u).", protocol);
	inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return -EINVAL;
}

static int init_l4_inner(struct sk_buff *skb, u8 protocol, unsigned int offset)
{
	switch (protocol) {
	case IPPROTO_TCP:
		if (!may_pull_keep(skb, offset + sizeof(struct tcphdr)))
			goto truncated;
		break;

	case IPPROTO_UDP:
		if (!may_pull_keep(skb, offset + sizeof(struct udphdr)))
			goto truncated;
		break;

	case IPPROTO_ICMP:
	case NEXTHDR_ICMP:
		if (!may_pull_keep(skb, offset + sizeof(struct icmphdr)))
			goto truncated;
		break;

	default:
		/*
		 * Why are we validating an error packet of a packet we couldn't have translated?
		 * Either an attack or shouldn't happen, so drop silently.
		 */
		log_debug("Inner packet has bogus layer 4 protocol.");
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}

	return 0;

truncated:
	log_debug("Inner packet is too small to contain its layer-4 header (proto %u).", protocol);
	inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return -EINVAL;
}

/**
 * Warning: Result is an inverted boolean. Zero means "no problem", nonzero is an error code and
 * therefore means "no".
 */
static int may_pull_ipv6_hdrs(struct sk_buff *skb, bool restore_ptrs)
{
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;
	int offset;
	bool pulled;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	offset = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr);
#else
	__be16 frag_offset;
	offset = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &nexthdr, &frag_offset);
#endif

	if (offset < 0) {
		log_debug("ipv6_skip_exthdr() returned negative (%d).", offset);
		return -EINVAL;
	}

	pulled = restore_ptrs ? may_pull_keep(skb, offset) : pskb_may_pull(skb, offset);
	if (!pulled) {
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
	struct ipv6hdr *hdr6;
	struct frag_hdr *hdr_frag;
	struct icmp6hdr *hdr_icmp;
	struct hdr_iterator iterator;
	unsigned int offset = skb_hdrs_len(skb);
	int error = -EINVAL;

	log_debug("Validating inner IPv6 packet.");

	if (!may_pull_keep(skb, offset + sizeof(struct ipv6hdr))) {
		log_debug("Length is too small to contain a basic IPv6 header.");
		goto truncated;
	}
	hdr6 = skb_jcb(skb)->payload;
	if (unlikely(hdr6->version != 6)) {
		log_debug("Version is not 6.");
		goto inhdr;
	}
	error = may_pull_ipv6_hdrs(skb, true);
	if (unlikely(error))
		goto truncated;

	hdr6 = skb_jcb(skb)->payload;
	hdr_iterator_init_truncated(&iterator, hdr6, skb_headlen(skb) - offset);
	error = iterate_till_end(&iterator, &hdr_frag);
	if (unlikely(error))
		goto truncated;

	if (unlikely(!is_first_fragment_ipv6(hdr_frag))) {
		log_debug("Inner packet is not a first fragment.");
		error = -EINVAL;
		goto inhdr;
	}

	offset = iterator.data - (void *) ipv6_hdr(skb);
	error = init_l4_inner(skb, iterator.hdr_type, offset);
	if (unlikely(error))
		return error;

	if (iterator.hdr_type == L4PROTO_ICMP) {
		hdr_icmp = ((void *) ipv6_hdr(skb)) + offset;
		if (unlikely(icmp6_has_inner_packet(hdr_icmp->icmp6_type))) {
			log_debug("Packet inside packet inside packet.");
			error = -EINVAL;
			goto inhdr;
		}
	}

	return 0;

truncated:
	inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return error;

inhdr:
	inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
	return error;
}

static int __skb_init_cb_ipv6(struct sk_buff *skb, bool is_fragment)
{
	struct jool_cb *cb;
	struct frag_hdr *fragment_hdr;
	struct hdr_iterator iterator;
	int l4hdr_offset;
	int error = -EINVAL;

#ifdef BENCHMARK
	cb = skb_jcb(skb);
	getnstimeofday(&cb->start_time);
#endif

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		goto truncated;

	if (unlikely(skb->len != sizeof(struct ipv6hdr) + ntohs(ipv6_hdr(skb)->payload_len)))
		goto inhdr;
	error = may_pull_ipv6_hdrs(skb, false);
	if (unlikely(error))
		goto truncated;

	hdr_iterator_init_truncated(&iterator, ipv6_hdr(skb),
			skb_tail_pointer(skb) - skb_network_header(skb));
	error = iterate_till_end(&iterator, &fragment_hdr);
	if (unlikely(error))
		goto inhdr;

	cb = skb_jcb(skb);
	cb->l3_proto = L3PROTO_IPV6;
	cb->is_inner = 0;
	cb->is_fragment = is_fragment;
	cb->original_skb = skb;

	l4hdr_offset = iterator.data - (void *) ipv6_hdr(skb);
	/*
	 * Note! skb->data is involved so this equation is delicate.
	 * In first fragments, the pointer must end in the transport header.
	 * In subsequent fragments, the pointer must end up in the payload.
	 */
	skb_set_transport_header(skb, skb_network_offset(skb) + l4hdr_offset);

	return init_l4(skb, iterator.hdr_type, is_first_fragment_ipv6(fragment_hdr));

truncated:
	inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return error;

inhdr:
	inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
	return error;
}

int skb_init_cb_ipv6(struct sk_buff *skb)
{
	int error;

	error = fail_if_shared(skb);
	if (error)
		return error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might change pointers,
	 * so you generally don't want to store them.
	 */

	error = __skb_init_cb_ipv6(skb, skb_shinfo(skb)->frag_list != NULL);
	if (unlikely(error))
		return error;

	if (skb_l4_proto(skb) == L4PROTO_ICMP) {
		__u8 type = icmp6_hdr(skb)->icmp6_type;

		if (icmp6_has_inner_packet(type)) {
			error = init_inner_packet6(skb);
			if (unlikely(error))
				return error;
		}

		if (nat64_is_stateless() && is_icmp6_info(icmp6_hdr(skb)->icmp6_type)
				&& is_fragmented_ipv6(get_extension_header(ipv6_hdr(skb), NEXTHDR_FRAGMENT))) {
			log_debug("Packet is a fragmented ping. Its checksum cannot be translated, "
					"so I'll just drop it.");
			return -EINVAL;
		}
	}

	/* If not a fragment, the next "while" will be omitted. */
	skb_walk_frags(skb, skb) {
		error = __skb_init_cb_ipv6(skb, true);
		if (unlikely(error))
			return error;
	}

	return 0;
}

static int init_inner_packet4(struct sk_buff *skb)
{
	struct iphdr *hdr4;
	struct icmphdr *l4_hdr;
	unsigned int l3_hdr_len;
	unsigned int offset = skb_hdrs_len(skb);
	int error = -EINVAL;

	log_debug("Validating IPv4 inner packet.");

	if (!may_pull_keep(skb, offset + sizeof(struct iphdr))) {
		log_debug("Inner packet is too small to contain a basic IPv4 header.");
		goto truncated;
	}

	hdr4 = skb_jcb(skb)->payload;
	if (unlikely(hdr4->version != 4)) {
		log_debug("Inner packet is not IPv4.");
		goto inhdr;
	}
	if (unlikely(hdr4->ihl < 5)) {
		log_debug("Inner packet's IHL is bogus.");
		goto inhdr;
	}

	l3_hdr_len = 4 * hdr4->ihl;

	if (!may_pull_keep(skb, l3_hdr_len)) {
		log_debug("Inner packet is too small to contain its IPv4 header.");
		goto truncated;
	}

	hdr4 = skb_jcb(skb)->payload;
	if (unlikely(ip_fast_csum((u8 *) hdr4, hdr4->ihl))) {
		log_debug("Inner packet's header checksum doesn't match.");
		goto inhdr;
	}
	if (unlikely(ntohs(hdr4->tot_len) < l3_hdr_len)) {
		log_debug("Inner packet's total length is bogus.");
		goto inhdr;
	}
	if (unlikely(!is_first_fragment_ipv4(hdr4))) {
		log_debug("Inner packet is not a first fragment...");
		goto inhdr;
	}

	error = init_l4_inner(skb, hdr4->protocol, offset + l3_hdr_len);
	if (unlikely(error))
		return error;

	hdr4 = skb_jcb(skb)->payload;
	if (hdr4->protocol == IPPROTO_ICMP) {
		l4_hdr = ((void *) hdr4) + l3_hdr_len;
		if (unlikely(icmp4_has_inner_packet(l4_hdr->type))) {
			log_debug("Packet inside packet inside packet.");
			error = -EINVAL;
			goto inhdr;
		}
	}

	return 0;

truncated:
	inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return error;

inhdr:
	inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
	return error;
}

static int __skb_init_cb_ipv4(struct sk_buff *skb, bool is_fragment)
{
	struct jool_cb *cb = skb_jcb(skb);
	struct iphdr *hdr4 = ip_hdr(skb);

#ifdef BENCHMARK
	getnstimeofday(&cb->start_time);
#endif

	cb->l3_proto = L3PROTO_IPV4;
	cb->is_inner = 0;
	cb->is_fragment = is_fragment;
	cb->original_skb = skb;
	/*
	 * Note! skb->data is involved so this equation is delicate.
	 * In first fragments, the pointer must end in the transport header.
	 * In subsequent fragments, the pointer must end up in the payload.
	 */
	skb_set_transport_header(skb, skb_network_offset(skb) + 4 * hdr4->ihl);

	return init_l4(skb, hdr4->protocol, is_first_fragment_ipv4(hdr4));
}

int skb_init_cb_ipv4(struct sk_buff *skb)
{
	int error;

	error = fail_if_shared(skb);
	if (error)
		return error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might change pointers,
	 * so you generally don't want to store them.
	 */

	error = __skb_init_cb_ipv4(skb, skb_shinfo(skb)->frag_list != NULL);
	if (unlikely(error))
		return error;

	if (skb_l4_proto(skb) == L4PROTO_ICMP) {
		__u8 type = icmp_hdr(skb)->type;

		if (icmp4_has_inner_packet(type)) {
			error = init_inner_packet4(skb);
			if (unlikely(error))
				return error;
		}

		if (nat64_is_stateless() && is_icmp4_info(type) && is_fragmented_ipv4(ip_hdr(skb))) {
			log_debug("Packet is a fragmented ping. Its checksum cannot be translated, "
					"so I'll just drop it.");
			return -EINVAL;
		}
	}

	skb_walk_frags(skb, skb) {
		if (unlikely(skb->len + 4 * ip_hdr(skb)->ihl != ntohs(ip_hdr(skb)->tot_len))) {
			inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
			return -EINVAL;
		}

		error = __skb_init_cb_ipv4(skb, true);
		if (unlikely(error))
			return error;
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

static void print_lengths(struct sk_buff *skb)
{
	pr_debug("Lengths:\n");
	pr_debug("\t	skb->len: %u", skb->len);
	pr_debug("\t	skb->data_len: %u\n", skb->data_len);
	pr_debug("\t	skb_pagelen(skb): %u\n", skb_pagelen(skb));
	pr_debug("\t	skb_len(skb): %u\n", skb_len(skb));
	pr_debug("\t	nh-th:%u th-p:%u l3:%u l4:%u l3+l4:%u\n",
			skb_transport_offset(skb) - skb_network_offset(skb),
			skb_payload_offset(skb) - skb_transport_offset(skb),
			skb_l3hdr_len(skb), skb_l4hdr_len(skb), skb_hdrs_len(skb));
	pr_debug("\t	skb_payload_len_frag(skb): %u\n", skb_payload_len_frag(skb));
	pr_debug("\t	skb_payload_len_pkt(skb): %u\n", skb_payload_len_pkt(skb));
	pr_debug("\t	skb_l3payload_len(skb): %u\n", skb_l3payload_len(skb));
	pr_debug("\t	skb_datagram_len(skb): %u\n", skb_datagram_len(skb));
	pr_debug("\t	frag_list:%p nr_frags:%u\n",
			skb_shinfo(skb)->frag_list, skb_shinfo(skb)->nr_frags);
}

static void print_l3_hdr(struct sk_buff *skb)
{
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag_header;
	struct iphdr *hdr4;
	struct in_addr addr4;
	unsigned int tmp;

	pr_debug("Layer 3 proto: %s", l3proto_to_string(skb_l3_proto(skb)));
	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV6:
		hdr6 = ipv6_hdr(skb);
		if (hdr6->version != 6)
			pr_debug("		version: %u\n", hdr6->version);
		tmp = (hdr6->priority << 4) | (hdr6->flow_lbl[0] >> 4);
		if (tmp != 0)
		pr_debug("		traffic class: %u\n", tmp);
		tmp = ((hdr6->flow_lbl[0] & 0xf) << 16) | (hdr6->flow_lbl[1] << 8) | hdr6->flow_lbl[0];
		if (tmp != 0)
			pr_debug("		flow label: %u\n", tmp);
		pr_debug("		payload length: %u\n", be16_to_cpu(hdr6->payload_len));
		pr_debug("		next header: %s (%u)\n", nexthdr_to_string(hdr6->nexthdr), hdr6->nexthdr);
		if (hdr6->hop_limit < 60)
			pr_debug("		hop limit: %u\n", hdr6->hop_limit);
		pr_debug("		source address: %pI6c\n", &hdr6->saddr);
		pr_debug("		destination address: %pI6c\n", &hdr6->daddr);

		if (hdr6->nexthdr == NEXTHDR_FRAGMENT) {
			frag_header = (struct frag_hdr *) (hdr6 + 1);
			pr_debug("Fragment header:\n");
			pr_debug("		next header: %s\n", nexthdr_to_string(frag_header->nexthdr));
			if (frag_header->reserved != 0)
				pr_debug("		reserved: %u\n", frag_header->reserved);
			pr_debug("		fragment offset: %u bytes\n", get_fragment_offset_ipv6(frag_header));
			pr_debug("		more fragments: %u\n", is_more_fragments_set_ipv6(frag_header));
			pr_debug("		identification: %u\n", be32_to_cpu(frag_header->identification));
		}
		break;

	case L3PROTO_IPV4:
		hdr4 = ip_hdr(skb);
		if (hdr4->version != 4)
			pr_debug("		version: %u\n", hdr4->version);
		if (hdr4->ihl != 5)
			pr_debug("		header length: %u\n", hdr4->ihl);
		if (hdr4->tos != 0)
			pr_debug("		type of service: %u\n", hdr4->tos);
		pr_debug("		total length: %u\n", be16_to_cpu(hdr4->tot_len));
		pr_debug("		identification: %u\n", be16_to_cpu(hdr4->id));
		pr_debug("		don't fragment: %u\n", is_dont_fragment_set(hdr4));
		pr_debug("		more fragments: %u\n", is_more_fragments_set_ipv4(hdr4));
		pr_debug("		fragment offset: %u bytes\n", get_fragment_offset_ipv4(hdr4));
		if (hdr4->ttl < 60)
			pr_debug("		time to live: %u\n", hdr4->ttl);
		pr_debug("		protocol: %s (%u)\n", protocol_to_string(hdr4->protocol), hdr4->protocol);
		pr_debug("		checksum: %x\n", be16_to_cpu((__force __be16) hdr4->check));
		addr4.s_addr = hdr4->saddr;
		pr_debug("		source address: %pI4\n", &addr4);
		addr4.s_addr = hdr4->daddr;
		pr_debug("		destination address: %pI4\n", &addr4);
		break;
	}
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

static void print_payload(struct sk_buff *skb)
{
	unsigned int offset;
	unsigned char *chara;

	pr_debug("Payload (paged data not included):");
	for (chara = skb_payload(skb); chara < skb_tail_pointer(skb); chara++) {
		offset = chara - (unsigned char *) skb_payload(skb);
		if (offset % 12 == 0)
			printk("\n\t\t");
		printk("%u ", *chara);
	}
	pr_debug("\n");
}

void skb_print(struct sk_buff *skb)
{
	pr_debug("----------------\n");

	if (!skb) {
		pr_debug("(null)\n");
		return;
	}

	print_lengths(skb);

	if (skb_network_header(skb))
		print_l3_hdr(skb);
	if (skb_transport_header(skb))
		print_l4_hdr(skb);
	print_payload(skb);

	skb_walk_frags(skb, skb) {
		skb_print(skb);
	}
}

int validate_icmp6_csum(struct sk_buff *skb)
{
	struct ipv6hdr *ip6_hdr;
	unsigned int datagram_len;
	__sum16 csum;

	if (skb_l4_proto(skb) != L4PROTO_ICMP)
		return 0;

	if (!is_icmp6_error(icmp6_hdr(skb)->icmp6_type))
		return 0;

	ip6_hdr = ipv6_hdr(skb);
	datagram_len = skb_datagram_len(skb);
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
	__sum16 csum;

	if (skb_l4_proto(skb) != L4PROTO_ICMP)
		return 0;

	if (!is_icmp4_error(icmp_hdr(skb)->type))
		return 0;

	csum = csum_fold(skb_checksum(skb, skb_transport_offset(skb), skb_datagram_len(skb), 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return -EINVAL;
	}

	return 0;
}
