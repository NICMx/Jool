#include "nat64/mod/common/packet.h"

#include <linux/version.h>
#include <linux/icmp.h>
#include <net/route.h>
#include "nat64/common/types.h"
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/stats.h"

struct pkt_metadata {
	bool has_frag_hdr;
	/* Offset is from skb->data. Do not use if has_frag_hdr is false. */
	unsigned int frag_offset;
	enum l4_protocol l4_proto;
	/* Offset is from skb->data. */
	unsigned int l4_offset;
	/* Offset is from skb->data. */
	unsigned int payload_offset;
};

#define skb_hdr_ptr(skb, offset, buffer) skb_header_pointer(skb, offset, sizeof(buffer), &buffer)

static bool has_inner_pkt4(__u8 icmp_type)
{
	return is_icmp4_error(icmp_type);
}

static bool has_inner_pkt6(__u8 icmp6_type)
{
	return is_icmp6_error(icmp6_type);
}

static int truncated6(struct sk_buff *skb, const char *what)
{
	log_debug("The %s seems truncated.", what);
	inc_stats_skb6(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return -EINVAL;
}

static int truncated4(struct sk_buff *skb, const char *what)
{
	log_debug("The %s seems truncated.", what);
	inc_stats_skb4(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return -EINVAL;
}

static int inhdr6(struct sk_buff *skb, const char *msg)
{
	log_debug("%s", msg);
	inc_stats_skb6(skb, IPSTATS_MIB_INHDRERRORS);
	return -EINVAL;
}

static int inhdr4(struct sk_buff *skb, const char *msg)
{
	log_debug("%s", msg);
	inc_stats_skb4(skb, IPSTATS_MIB_INHDRERRORS);
	return -EINVAL;
}

static void *offset_to_ptr(struct sk_buff *skb, unsigned int offset)
{
	return ((void *) skb->data) + offset;
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
 * Walks through skb's headers, collecting data and adding it to meta.
 *
 * @hdr6_offset number of bytes between skb->data and the IPv6 header.
 *
 * BTW: You might want to read summarize_skb4() first, since it's a lot simpler.
 */
static int summarize_skb6(struct sk_buff *skb, unsigned int hdr6_offset, struct pkt_metadata *meta)
{
	union {
		struct ipv6_opt_hdr opt;
		struct frag_hdr frag;
		struct tcphdr tcp;
	} buffer;
	union {
		struct ipv6_opt_hdr *opt;
		struct frag_hdr *frag;
		struct tcphdr *tcp;
	} ptr;

	u8 nexthdr;
	unsigned int offset;
	bool is_first = true;

	nexthdr = ((struct ipv6hdr *) (skb_network_header(skb) + hdr6_offset))->nexthdr;
	offset = hdr6_offset + sizeof(struct ipv6hdr);

	meta->has_frag_hdr = false;

	do {
		switch (nexthdr) {
		case NEXTHDR_TCP:
			meta->l4_proto = L4PROTO_TCP;
			meta->l4_offset = offset;
			meta->payload_offset = offset;

			if (is_first) {
				ptr.tcp = skb_hdr_ptr(skb, offset, buffer.tcp);
				if (!ptr.tcp)
					return truncated6(skb, "TCP header");
				meta->payload_offset += tcp_hdr_len(ptr.tcp);
			}

			return 0;

		case NEXTHDR_UDP:
			meta->l4_proto = L4PROTO_UDP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first ? (offset + sizeof(struct udphdr)) : offset;
			return 0;

		case NEXTHDR_ICMP:
			meta->l4_proto = L4PROTO_ICMP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first ? (offset + sizeof(struct icmp6hdr)) : offset;
			return 0;

		case NEXTHDR_FRAGMENT:
			ptr.frag = skb_hdr_ptr(skb, offset, buffer.frag);
			if (!ptr.frag)
				return truncated6(skb, "fragment header");

			meta->has_frag_hdr = true;
			meta->frag_offset = offset;
			is_first = is_first_frag6(ptr.frag);

			offset += sizeof(struct frag_hdr);
			nexthdr = ptr.frag->nexthdr;
			break;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST:
			ptr.opt = skb_hdr_ptr(skb, offset, buffer.opt);
			if (!ptr.opt)
				return truncated6(skb, "extension header");

			offset += 8 + 8 * ptr.opt->hdrlen;
			nexthdr = ptr.opt->nexthdr;
			break;

		default:
			meta->l4_proto = L4PROTO_OTHER;
			meta->l4_offset = offset;
			meta->payload_offset = offset;
			return 0;
		}
	} while (true);

	return 0; /* whatever. */
}

static int validate_inner6(struct sk_buff *skb, struct pkt_metadata *outer_meta)
{
	union {
		struct ipv6hdr ip6;
		struct frag_hdr frag;
		struct icmp6hdr icmp;
	} buffer;
	union {
		struct ipv6hdr *ip6;
		struct frag_hdr *frag;
		struct icmp6hdr *icmp;
	} ptr;

	struct pkt_metadata meta;
	int error;

	ptr.ip6 = skb_hdr_ptr(skb, outer_meta->payload_offset, buffer.ip6);
	if (!ptr.ip6)
		return truncated6(skb, "inner IPv6 header");
	if (unlikely(ptr.ip6->version != 6))
		return inhdr6(skb, "Version is not 6.");

	error = summarize_skb6(skb, outer_meta->payload_offset, &meta);
	if (error)
		return error;

	if (meta.has_frag_hdr) {
		ptr.frag = skb_hdr_ptr(skb, meta.frag_offset, buffer.frag);
		if (!ptr.frag)
			return truncated6(skb, "inner fragment header");
		if (!is_first_frag6(ptr.frag))
			return inhdr6(skb, "Inner packet is not a first fragment.");
	}

	if (meta.l4_proto == L4PROTO_ICMP) {
		ptr.icmp = skb_hdr_ptr(skb, meta.l4_offset, buffer.icmp);
		if (!ptr.icmp)
			return truncated6(skb, "inner ICMPv6 header");
		if (has_inner_pkt6(ptr.icmp->icmp6_type))
			return inhdr6(skb, "Packet inside packet inside packet.");
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return -EINVAL;
	}

	return 0;
}

static int handle_icmp6(struct sk_buff *skb, struct pkt_metadata *meta)
{
	union {
		struct icmp6hdr icmp;
		struct frag_hdr frag;
	} buffer;
	union {
		struct icmp6hdr *icmp;
		struct frag_hdr *frag;
	} ptr;
	int error;

	ptr.icmp = skb_hdr_ptr(skb, meta->l4_offset, buffer.icmp);
	if (!ptr.icmp)
		return truncated6(skb, "ICMPv6 header");

	if (has_inner_pkt6(ptr.icmp->icmp6_type)) {
		error = validate_inner6(skb, meta);
		if (error)
			return error;
	}

	if (xlat_is_siit() && meta->has_frag_hdr && is_icmp6_info(ptr.icmp->icmp6_type)) {
		ptr.frag = skb_hdr_ptr(skb, meta->frag_offset, buffer.frag);
		if (!ptr.frag)
			return truncated6(skb, "fragment header");
		if (is_fragmented_ipv6(ptr.frag)) {
			log_debug("Packet is a fragmented ping; its checksum cannot be translated.");
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * As a contract, pkt_destroy() doesn't need to be called if this fails.
 * (Just like other init functions.)
 */
int pkt_init_ipv6(struct packet *pkt, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might
	 * change pointers, so you generally don't want to store them.
	 */

#ifdef BENCHMARK
	getnstimeofday(&pkt->start_time);
#endif

	error = fail_if_shared(skb);
	if (error)
		return error;

	if (skb->len != get_tot_len_ipv6(skb))
		return inhdr6(skb, "Packet size doesn't match the IPv6 header's payload length field.");

	error = summarize_skb6(skb, skb_network_offset(skb), &meta);
	if (error)
		return error;

	if (meta.l4_proto == L4PROTO_ICMP) {
		/* Do not move this to summarize_skb6(), because it risks infinite recursion. */
		error = handle_icmp6(skb, &meta);
		if (error)
			return error;
	}

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return -EINVAL;
	}

	pkt->skb = skb;
	pkt->l3_proto = L3PROTO_IPV6;
	pkt->l4_proto = meta.l4_proto;
	pkt->is_inner = 0;
	pkt->is_hairpin = false;
	pkt->hdr_frag = meta.has_frag_hdr ? offset_to_ptr(skb, meta.frag_offset) : NULL;
	skb_set_transport_header(skb, meta.l4_offset);
	pkt->payload = offset_to_ptr(skb, meta.payload_offset);
	pkt->original_pkt = pkt;

	return 0;
}

static int validate_inner4(struct sk_buff *skb, struct pkt_metadata *meta)
{
	union {
		struct iphdr ip4;
		struct tcphdr tcp;
	} buffer;
	union {
		struct iphdr *ip4;
		struct tcphdr *tcp;
	} ptr;
	unsigned int ihl;
	unsigned int offset = meta->payload_offset;

	ptr.ip4 = skb_hdr_ptr(skb, offset, buffer.ip4);
	if (!ptr.ip4)
		return truncated4(skb, "inner IPv4 header");

	ihl = ptr.ip4->ihl << 2;
	if (ptr.ip4->version != 4)
		return inhdr4(skb, "Inner packet is not IPv4.");
	if (ihl < 20)
		return inhdr4(skb, "Inner packet's IHL is bogus.");
	if (ntohs(ptr.ip4->tot_len) < ihl)
		return inhdr4(skb, "Inner packet's total length is bogus.");
	if (!is_first_frag4(ptr.ip4))
		return inhdr4(skb, "Inner packet is not first fragment.");

	offset += ihl;

	switch (ptr.ip4->protocol) {
	case IPPROTO_TCP:
		ptr.tcp = skb_hdr_ptr(skb, offset, buffer.tcp);
		if (!ptr.tcp)
			return truncated4(skb, "inner TCP header");
		offset += tcp_hdr_len(ptr.tcp);
		break;
	case IPPROTO_UDP:
		offset += sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		offset += sizeof(struct icmphdr);
		break;
	}

	if (!pskb_may_pull(skb, offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return -EINVAL;
	}

	return 0;
}

static int handle_icmp4(struct sk_buff *skb, struct pkt_metadata *meta)
{
	struct icmphdr buffer, *ptr;
	int error;

	ptr = skb_hdr_ptr(skb, meta->l4_offset, buffer);
	if (!ptr)
		return truncated4(skb, "ICMP header");

	if (has_inner_pkt4(ptr->type)) {
		error = validate_inner4(skb, meta);
		if (error)
			return error;
	}

	if (xlat_is_siit() && is_icmp4_info(ptr->type) && is_fragmented_ipv4(ip_hdr(skb))) {
		log_debug("Packet is a fragmented ping; its checksum cannot be translated.");
		return -EINVAL;
	}

	return 0;
}

static int summarize_skb4(struct sk_buff *skb, struct pkt_metadata *meta)
{
	struct iphdr *hdr4 = ip_hdr(skb);
	unsigned int offset = skb_network_offset(skb) + (hdr4->ihl << 2);

	meta->has_frag_hdr = false;
	meta->l4_offset = offset;
	meta->payload_offset = offset;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		meta->l4_proto = L4PROTO_TCP;
		if (is_first_frag4(hdr4)) {
			struct tcphdr buffer, *ptr;
			ptr = skb_hdr_ptr(skb, offset, buffer);
			if (!ptr)
				return truncated4(skb, "TCP header");
			meta->payload_offset += tcp_hdr_len(ptr);
		}
		return 0;

	case IPPROTO_UDP:
		meta->l4_proto = L4PROTO_UDP;
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct udphdr);
		return 0;

	case IPPROTO_ICMP:
		meta->l4_proto = L4PROTO_ICMP;
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct icmphdr);
		return handle_icmp4(skb, meta);
	}

	meta->l4_proto = L4PROTO_OTHER;
	return 0;
}

/**
 * As a contract, pkt_destroy() doesn't need to be called if this fails.
 * (Just like other init functions.)
 */
int pkt_init_ipv4(struct packet *pkt, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	/*
	 * Careful in this function and subfunctions. pskb_may_pull() might
	 * change pointers, so you generally don't want to store them.
	 */

#ifdef BENCHMARK
	getnstimeofday(&pkt->start_time);
#endif

	error = fail_if_shared(skb);
	if (error)
		return error;

	error = summarize_skb4(skb, &meta);
	if (error)
		return error;

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return -EINVAL;
	}

	pkt->skb = skb;
	pkt->l3_proto = L3PROTO_IPV4;
	pkt->l4_proto = meta.l4_proto;
	pkt->is_inner = false;
	pkt->is_hairpin = false;
	pkt->hdr_frag = NULL;
	skb_set_transport_header(skb, meta.l4_offset);
	pkt->payload = offset_to_ptr(skb, meta.payload_offset);
	pkt->original_pkt = pkt;

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

static void print_lengths(struct packet *pkt)
{
	pr_debug("Lengths:\n");
	pr_debug("\t	skb->len: %u", pkt->skb->len);
	pr_debug("\t	skb->data_len: %u\n", pkt->skb->data_len);
	pr_debug("\t	skb_pagelen(skb): %u\n", skb_pagelen(pkt->skb));
	pr_debug("\t	pkt_len(pkt): %u\n", pkt_len(pkt));
	pr_debug("\t	nh-th:%u th-p:%u l3:%u l4:%u l3+l4:%u\n",
			skb_transport_offset(pkt->skb) - skb_network_offset(pkt->skb),
			pkt_payload_offset(pkt) - skb_transport_offset(pkt->skb),
			pkt_l3hdr_len(pkt), pkt_l4hdr_len(pkt), pkt_hdrs_len(pkt));
	pr_debug("\t	pkt_payload_len_frag(pkt): %u\n", pkt_payload_len_frag(pkt));
	pr_debug("\t	pkt_payload_len_pkt(pkt): %u\n", pkt_payload_len_pkt(pkt));
	pr_debug("\t	pkt_l3payload_len(pkt): %u\n", pkt_l3payload_len(pkt));
	pr_debug("\t	pkt_datagram_len(pkt): %u\n", pkt_datagram_len(pkt));
	pr_debug("\t	frag_list:%p nr_frags:%u\n",
			skb_shinfo(pkt->skb)->frag_list, skb_shinfo(pkt->skb)->nr_frags);
}

static void print_l3_hdr(struct packet *pkt)
{
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag_header;
	struct iphdr *hdr4;
	struct in_addr addr4;
	unsigned int tmp;

	pr_debug("Layer 3 proto: %s", l3proto_to_string(pkt_l3_proto(pkt)));
	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV6:
		hdr6 = pkt_ip6_hdr(pkt);
		if (hdr6->version != 6)
			pr_debug("		version: %u\n", hdr6->version);
		tmp = (hdr6->priority << 4) | (hdr6->flow_lbl[0] >> 4);
		if (tmp != 0)
		pr_debug("		traffic class: %u\n", tmp);
		tmp = ((hdr6->flow_lbl[0] & 0xFU) << 16) | (hdr6->flow_lbl[1] << 8) | hdr6->flow_lbl[2];
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
			pr_debug("		more fragments: %u\n", is_mf_set_ipv6(frag_header));
			pr_debug("		identification: %u\n", be32_to_cpu(frag_header->identification));
		}
		break;

	case L3PROTO_IPV4:
		hdr4 = pkt_ip4_hdr(pkt);
		if (hdr4->version != 4)
			pr_debug("		version: %u\n", hdr4->version);
		if (hdr4->ihl != 5)
			pr_debug("		header length: %u\n", hdr4->ihl);
		if (hdr4->tos != 0)
			pr_debug("		type of service: %u\n", hdr4->tos);
		pr_debug("		total length: %u\n", be16_to_cpu(hdr4->tot_len));
		pr_debug("		identification: %u\n", be16_to_cpu(hdr4->id));
		pr_debug("		don't fragment: %u\n", is_df_set(hdr4));
		pr_debug("		more fragments: %u\n", is_mf_set_ipv4(hdr4));
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

static void print_l4_hdr(struct packet *pkt)
{
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct icmphdr *icmp_header;

	pr_debug("Layer 4 proto: %s\n", l4proto_to_string(pkt_l4_proto(pkt)));
	switch (pkt_l4_proto(pkt)) {
	case L4PROTO_TCP:
		tcp_header = pkt_tcp_hdr(pkt);
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
		udp_header = pkt_udp_hdr(pkt);
		pr_debug("		source port: %u\n", be16_to_cpu(udp_header->source));
		pr_debug("		destination port: %u\n", be16_to_cpu(udp_header->dest));
		pr_debug("		length: %u\n", be16_to_cpu(udp_header->len));
		pr_debug("		checksum: %x\n", be16_to_cpu((__force __be16) udp_header->check));
		break;

	case L4PROTO_ICMP:
		icmp_header = pkt_icmp4_hdr(pkt);
		pr_debug("		type: %u\n", icmp_header->type);
		pr_debug("		code: %u\n", icmp_header->code);
		pr_debug("		checksum: %x\n", be16_to_cpu((__force __be16) icmp_header->checksum));
		pr_debug("		un: %x\n", be32_to_cpu(icmp_header->un.gateway));
		break;

	case L4PROTO_OTHER:
		break;
	}
}

static void print_payload(struct packet *pkt)
{
	unsigned int offset;
	unsigned char *chara;

	pr_debug("Payload (paged data not included):");
	for (chara = pkt_payload(pkt); chara < skb_tail_pointer(pkt->skb); chara++) {
		offset = chara - (unsigned char *) pkt_payload(pkt);
		if (offset % 12 == 0)
			printk("\n\t\t");
		printk("%u ", *chara);
	}
	pr_debug("\n");
}

void pkt_print(struct packet *pkt)
{
	pr_debug("----------------\n");

	if (!pkt) {
		pr_debug("(null)\n");
		return;
	}

	print_lengths(pkt);

	if (skb_network_header(pkt->skb))
		print_l3_hdr(pkt);
	if (skb_transport_header(pkt->skb))
		print_l4_hdr(pkt);
	print_payload(pkt);
}
