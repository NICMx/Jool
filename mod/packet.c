#include "nat64/mod/packet.h"

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

/** Cache for struct fragments, for efficient allocation. */
static struct kmem_cache *frag_cache;
/** Cache for struct packets, for efficient allocation. */
static struct kmem_cache *pkt_cache;

int pktmod_init(void)
{
	pkt_cache = kmem_cache_create("jool_packets", sizeof(struct packet), 0, 0, NULL);
	if (!pkt_cache) {
		log_err("Could not allocate the packet cache.");
		return -ENOMEM;
	}

	frag_cache = kmem_cache_create("jool_fragments", sizeof(struct fragment), 0, 0, NULL);
	if (!frag_cache) {
		log_err("Could not allocate the fragment cache.");
		kmem_cache_destroy(pkt_cache);
		return -ENOMEM;
	}

	return 0;
}

void pktmod_destroy(void)
{
	kmem_cache_destroy(pkt_cache);
	kmem_cache_destroy(frag_cache);
}

int frag_create_empty(struct fragment **out)
{
	struct fragment *frag;

	frag = kmem_cache_alloc(frag_cache, GFP_ATOMIC);
	if (!frag) {
		log_debug("Could not allocate a struct fragment.");
		inc_stats(skb, IPSTATS_MIB_INDISCARDS);
		return -ENOMEM;
	}

	memset(frag, 0, sizeof(*frag));
	INIT_LIST_HEAD(&frag->list_hook);

	*out = frag;
	return 0;
}

int frag_create_from_skb(struct sk_buff *skb, struct fragment **frag)
{
	__u8 *first_byte;
	__u8 first_4_bits;
	int error;

	first_byte = skb_network_header(skb);
	first_4_bits = (*first_byte) >> 4;

	/* We can't use skb->protocol because it isn't set during the LOCAL_OUT Netfilter chains. */
	switch (first_4_bits) {
	case 4:
		error = frag_create_from_buffer_ipv4(skb_network_header(skb), skb->len, false, frag, skb);
		break;
	case 6:
		error = frag_create_from_buffer_ipv6(skb_network_header(skb), skb->len, false, frag, skb);
		break;
	default:
		log_debug("Unsupported network protocol: %u", first_4_bits);
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		return -EINVAL;
	}

	if (!error) {
		(*frag)->skb = skb;
		/* We no longer need this really, but I'll keep it JIC. */
		skb_set_transport_header(skb, (*frag)->l3_hdr.len);
	}

	return error;
}

static int validate_lengths_tcp(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_TCP_HDR_LEN) {
		log_debug("Packet is too small to contain a basic TCP header.");
		inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
		return -EINVAL;
	}

	return 0;
}

static int validate_lengths_udp(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_UDP_HDR_LEN) {
		log_debug("Packet is too small to contain a UDP header.");
		inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
		return -EINVAL;
	}

	return 0;
}

static int validate_lengths_icmp6(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP6_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv6 header.");
		inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
		return -EINVAL;
	}

	return 0;
}

static int validate_lengths_icmp4(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP4_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv4 header.");
		inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
		return -EINVAL;
	}

	return 0;
}

static int validate_ipv6_integrity(struct ipv6hdr *hdr, unsigned int len, bool is_truncated,
		struct hdr_iterator *iterator)
{
	enum hdr_iterator_result result;

	if (len < MIN_IPV6_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IPv6 header.");
		inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
		return -EINVAL;
	}
	if (!is_truncated && len != MIN_IPV6_HDR_LEN + be16_to_cpu(hdr->payload_len)) {
		log_debug("The packet's length does not match the IPv6 header's payload length field.");
		inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
		return -EINVAL;
	}

	hdr_iterator_init(iterator, hdr);
	result = hdr_iterator_last(iterator);

	switch (result) {
	case HDR_ITERATOR_SUCCESS:
		WARN(true, "Iterator reports there are headers beyond the payload.");
		inc_stats(skb, IPSTATS_MIB_INDISCARDS);
		break;
	case HDR_ITERATOR_END:
		return 0;
	case HDR_ITERATOR_UNSUPPORTED:
		log_debug("Packet contains an Authentication or ESP header, "
				"which I'm not supposed to support (RFC 6146 section 5.1).");
		inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
		/* TODO (issue #57) we're missing a ICMPv6 error (type 4, code 1) here. */
		break;
	case HDR_ITERATOR_OVERFLOW:
		log_debug("IPv6 extension header analysis ran past the end of the packet. "
				"Packet seems corrupted; ignoring.");
		inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
		break;
	}

	return -EINVAL;
}

static int init_ipv6_l3_hdr(struct fragment *frag, struct ipv6hdr *hdr6,
		struct hdr_iterator *iterator)
{
	frag->l3_hdr.proto = L3PROTO_IPV6;
	/* IPv6 header length = transport header offset - IPv6 header offset. */
	frag->l3_hdr.len = iterator->data - (void *) hdr6;
	frag->l3_hdr.ptr = hdr6;
	frag->l3_hdr.ptr_needs_kfree = false;

	return 0;
}

static int init_ipv6_l3_payload(struct fragment *frag, struct ipv6hdr *hdr6, unsigned int len,
		struct hdr_iterator *iterator)
{
	struct frag_hdr *frag_header;
	int error;

	frag_header = get_extension_header(hdr6, NEXTHDR_FRAGMENT);
	if (frag_header == NULL || get_fragment_offset_ipv6(frag_header) == 0) {
		frag->l4_hdr.ptr = iterator->data;

 		switch (iterator->hdr_type) {
		case NEXTHDR_TCP:
			error = validate_lengths_tcp(len, frag->l3_hdr.len);
			if (error)
				return error;

			frag->l4_hdr.proto = L4PROTO_TCP;
			frag->l4_hdr.len = 4 * frag_get_tcp_hdr(frag)->doff;
			break;

		case NEXTHDR_UDP:
			error = validate_lengths_udp(len, frag->l3_hdr.len);
			if (error)
				return error;

			frag->l4_hdr.proto = L4PROTO_UDP;
			frag->l4_hdr.len = sizeof(struct udphdr);
			break;

		case NEXTHDR_ICMP:
			error = validate_lengths_icmp6(len, frag->l3_hdr.len);
			if (error)
				return error;

			frag->l4_hdr.proto = L4PROTO_ICMP;
			frag->l4_hdr.len = sizeof(struct icmp6hdr);
			break;

		default:
			log_debug("Unsupported layer 4 protocol: %d", iterator->hdr_type);
			inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
			icmp64_send(frag, ICMPERR_PROTO_UNREACHABLE, 0);
			return -EINVAL;
		}

		frag->payload.len = len - frag->l3_hdr.len - frag->l4_hdr.len;
		frag->payload.ptr = frag->l4_hdr.ptr + frag->l4_hdr.len;

	} else {
		frag->l4_hdr.proto = L4PROTO_NONE;
		frag->l4_hdr.len = 0;
		frag->l4_hdr.ptr = NULL;
		frag->payload.len = iterator->limit - iterator->data;
		frag->payload.ptr = iterator->data;
	}

	frag->l4_hdr.ptr_needs_kfree = false;
	frag->payload.ptr_needs_kfree = false;

	return 0;
}

int frag_create_from_buffer_ipv6(unsigned char *buffer, unsigned int len, bool is_truncated,
		struct fragment **out_frag, struct sk_buff *skb)
{
	struct ipv6hdr *hdr = (struct ipv6hdr *) buffer;
	struct fragment *frag;
	struct hdr_iterator iterator;
	int error;

	error = validate_ipv6_integrity(hdr, len, is_truncated, &iterator);
	if (error)
		return error;

	frag = kmem_cache_alloc(frag_cache, GFP_ATOMIC);
	if (!frag) {
		log_debug("Cannot allocate a struct fragment.");
		inc_stats(skb, IPSTATS_MIB_INDELIVERS);
		return -ENOMEM;
	}

	frag->skb = NULL;
	frag->original_skb = skb;
	/*
	 * If you're comparing this to frag_create_from_buffer_ipv4(), keep in mind that
	 * ip6_route_input() is not exported for dynamic modules to use (and linux doesn't know a route
	 * to the NAT64 prefix anyway), so we have to test the shit out of kernel IPv6 functions which
	 * might dereference the dst_entries of the skbs.
	 * We already know of a bug in Linux 3.12 that does exactly that, see icmp_wrapper.c.
	 */

	error = init_ipv6_l3_hdr(frag, hdr, &iterator);
	if (error)
		goto fail;
	error = init_ipv6_l3_payload(frag, hdr, len, &iterator);
	if (error)
		goto fail;

	INIT_LIST_HEAD(&frag->list_hook);

	*out_frag = frag;
	return 0;

fail:
	kmem_cache_free(frag_cache, frag);
	return error;
}

static int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated)
{
	u16 ip4_hdr_len;

	if (len < MIN_IPV4_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IP header.");
		/* Even if we expect it to be truncated, this length is unacceptable. */
		goto truncated;
	}
	if (hdr->ihl < 5) {
		log_debug("Packet's IHL field is too small.");
		goto bad_hdr;
	}
	if (ip_fast_csum((u8 *) hdr, hdr->ihl)) {
		log_debug("Packet's IPv4 checksum is incorrect.");
		goto bad_hdr;
	}

	if (is_truncated)
		return 0;

	ip4_hdr_len = 4 * hdr->ihl;
	if (len < ip4_hdr_len) {
		log_debug("Packet is too small to contain the IP header + options.");
		goto truncated;
	}
	if (len != be16_to_cpu(hdr->tot_len)) {
		log_debug("The packet's length does not equal the IPv4 header's lengh field.");
		goto bad_hdr;
	}

	return 0;

bad_hdr:
	inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
	return -EINVAL;

truncated:
	inc_stats(skb, IPSTATS_MIB_INTRUNCATEDPKTS);
	return -EINVAL;
}

static int init_ipv4_l3_hdr(struct fragment *frag, struct iphdr *hdr)
{
	frag->l3_hdr.proto = L3PROTO_IPV4;
	frag->l3_hdr.len = 4 * hdr->ihl;
	frag->l3_hdr.ptr = hdr;
	frag->l3_hdr.ptr_needs_kfree = false;

	return 0;
}

static int init_ipv4_l3_payload(struct fragment *frag, struct iphdr *hdr4, unsigned int len)
{
	u16 fragment_offset;
	int error;

	fragment_offset = get_fragment_offset_ipv4(hdr4);
	if (fragment_offset == 0) {
		frag->l4_hdr.ptr = frag->l3_hdr.ptr + frag->l3_hdr.len;
		switch (hdr4->protocol) {
		case IPPROTO_TCP:
			error = validate_lengths_tcp(len, frag->l3_hdr.len);
			if (error)
				return error;

			frag->l4_hdr.proto = L4PROTO_TCP;
			frag->l4_hdr.len = 4 * frag_get_tcp_hdr(frag)->doff;
			break;

		case IPPROTO_UDP:
			error = validate_lengths_udp(len, frag->l3_hdr.len);
			if (error)
				return error;

			frag->l4_hdr.proto = L4PROTO_UDP;
			frag->l4_hdr.len = sizeof(struct udphdr);
			break;

		case IPPROTO_ICMP:
			error = validate_lengths_icmp4(len, frag->l3_hdr.len);
			if (error)
				return error;

			frag->l4_hdr.proto = L4PROTO_ICMP;
			frag->l4_hdr.len = sizeof(struct icmphdr);
			break;

		default:
			log_debug("Unsupported layer 4 protocol: %d", hdr4->protocol);
			inc_stats(skb, IPSTATS_MIB_INUNKNOWNPROTOS);
			icmp64_send(frag, ICMPERR_PROTO_UNREACHABLE, 0);
			return -EINVAL;
		}

		frag->payload.ptr = frag->l4_hdr.ptr + frag->l4_hdr.len;

	} else {
		frag->l4_hdr.proto = L4PROTO_NONE;
		frag->l4_hdr.len = 0;
		frag->l4_hdr.ptr = NULL;
		frag->payload.ptr = frag->l3_hdr.ptr + frag->l3_hdr.len;
	}

	frag->l4_hdr.ptr_needs_kfree = false;
	frag->payload.len = len - frag->l3_hdr.len - frag->l4_hdr.len;
	frag->payload.ptr_needs_kfree = false;

	return 0;
}

int frag_create_from_buffer_ipv4(unsigned char *buffer, unsigned int len, bool is_truncated,
		struct fragment **out_frag, struct sk_buff *skb)
{
	struct iphdr *hdr = (struct iphdr *) buffer;
	struct fragment *frag;
	int error;

	error = validate_ipv4_integrity(hdr, len, is_truncated);
	if (error)
		return error;

	frag = kmem_cache_alloc(frag_cache, GFP_ATOMIC);
	if (!frag) {
		log_debug("Cannot allocate a struct fragment.");
		inc_stats(skb, IPSTATS_MIB_INDISCARDS);
		return -ENOMEM;
	}

	frag->skb = NULL;
	frag->original_skb = skb;

#ifndef UNIT_TESTING
	if (skb && skb_rtable(skb) == NULL) {
		/*
		 * Some kernel functions assume that the incoming packet is already routed.
		 * Because they seem to pop up where we least expect them, we'll just route every incoming
		 * packet, regardless of whether we end up calling one of those functions.
		 */

		error = ip_route_input(skb, hdr->daddr, hdr->saddr, hdr->tos, skb->dev);
		if (error) {
			log_debug("ip_route_input failed: %d", error);
			goto fail;
		}
	}
#endif

	error = init_ipv4_l3_hdr(frag, hdr);
	if (error)
		goto fail;
	error = init_ipv4_l3_payload(frag, hdr, len);
	if (error)
		goto fail;

	INIT_LIST_HEAD(&frag->list_hook);

	*out_frag = frag;
	return 0;

fail:
	kmem_cache_free(frag_cache, frag);
	return error;
}

/**
 * Joins frag.l3_hdr, frag.l4_hdr and frag.payload into a single packet, placing the result in
 * frag.skb.
 *
 * Assumes that frag.skb is NULL (Hence, frag->*.ptr_belongs_to_skb are false).
 */
int frag_create_skb(struct fragment *frag)
{
	struct sk_buff *new_skb;
	bool has_l4_hdr;

	new_skb = alloc_skb(LL_MAX_HEADER /* kernel's reserved + layer 2. */
			+ frag->l3_hdr.len /* layer 3. */
			+ frag->l4_hdr.len /* layer 4. */
			+ frag->payload.len, /* packet data. */
			GFP_ATOMIC);
	if (!new_skb) {
		log_debug("New packet allocation failed.");
		inc_stats(skb, IPSTATS_MIB_INDISCARDS);
		return -ENOMEM;
	}
	frag->skb = new_skb;

	has_l4_hdr = (frag->l4_hdr.ptr != NULL);

	skb_reserve(new_skb, LL_MAX_HEADER);
	skb_put(new_skb, frag->l3_hdr.len + frag->l4_hdr.len + frag->payload.len);

	skb_reset_mac_header(new_skb);
	skb_reset_network_header(new_skb);
	if (has_l4_hdr)
		skb_set_transport_header(new_skb, frag->l3_hdr.len);

	memcpy(skb_network_header(new_skb), frag->l3_hdr.ptr, frag->l3_hdr.len);
	if (has_l4_hdr) {
		memcpy(skb_transport_header(new_skb), frag->l4_hdr.ptr, frag->l4_hdr.len);
		memcpy(skb_transport_header(new_skb) + frag->l4_hdr.len, frag->payload.ptr, frag->payload.len);
	} else {
		memcpy(skb_network_header(new_skb) + frag->l3_hdr.len, frag->payload.ptr, frag->payload.len);
	}

	if (frag->l3_hdr.ptr_needs_kfree)
		kfree(frag->l3_hdr.ptr);
	if (frag->l4_hdr.ptr_needs_kfree)
		kfree(frag->l4_hdr.ptr);
	if (frag->payload.ptr_needs_kfree)
		kfree(frag->payload.ptr);

	frag->l3_hdr.ptr = skb_network_header(new_skb);
	if (has_l4_hdr) {
		frag->l4_hdr.ptr = skb_transport_header(new_skb);
		frag->payload.ptr = skb_transport_header(new_skb) + frag->l4_hdr.len;
	} else {
		frag->l4_hdr.ptr = NULL;
		frag->payload.ptr = frag->l3_hdr.ptr + frag->l3_hdr.len;
	}

	frag->l3_hdr.ptr_needs_kfree = false;
	frag->l4_hdr.ptr_needs_kfree = false;
	frag->payload.ptr_needs_kfree = false;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV4:
		new_skb->protocol = htons(ETH_P_IP);
		break;
	case L3PROTO_IPV6:
		new_skb->protocol = htons(ETH_P_IPV6);
		break;
	}

	return 0;
}

bool frag_is_fragmented(struct fragment *frag)
{
	struct iphdr *hdr4;
	struct frag_hdr *hdr_frag;
	__u16 fragment_offset = 0;
	bool mf = false;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV4:
		hdr4 = frag_get_ipv4_hdr(frag);
		fragment_offset = get_fragment_offset_ipv4(hdr4);
		mf = is_more_fragments_set_ipv4(hdr4);
		break;

	case L3PROTO_IPV6:
		hdr_frag = frag_get_fragment_hdr(frag);
		if (!hdr_frag)
			return false;
		fragment_offset = get_fragment_offset_ipv6(hdr_frag);
		mf = is_more_fragments_set_ipv6(hdr_frag);
		break;
	}

	return (fragment_offset != 0) || (mf);
}

void frag_kfree(struct fragment *frag)
{
	if (!frag)
		return;

	if (frag->skb)
		kfree_skb(frag->skb);
	if (frag->l3_hdr.ptr_needs_kfree)
		kfree(frag->l3_hdr.ptr);
	if (frag->l4_hdr.ptr_needs_kfree)
		kfree(frag->l4_hdr.ptr);
	if (frag->payload.ptr_needs_kfree)
		kfree(frag->payload.ptr);

	list_del(&frag->list_hook);

	kmem_cache_free(frag_cache, frag);
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
	case L4PROTO_TCP:
		return "TCP";
	case L4PROTO_UDP:
		return "UDP";
	case L4PROTO_ICMP:
		return "ICMP";
	}

	return "Don't know";
}

void frag_print(struct fragment *frag)
{
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag_header;
	struct iphdr *hdr4;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct in_addr addr4;

	if (!frag) {
		pr_debug("(null)\n");
		return;
	}

	pr_debug("Layer 3 - proto:%s length:%u kfree:%d\n", l3proto_to_string(frag->l3_hdr.proto),
			frag->l3_hdr.len, frag->l3_hdr.ptr_needs_kfree);
	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV6:
		hdr6 = frag_get_ipv6_hdr(frag);
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
		hdr4 = frag_get_ipv4_hdr(frag);
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

	pr_debug("Layer 4 - proto:%s length:%u kfree:%d\n", l4proto_to_string(frag->l4_hdr.proto),
			frag->l4_hdr.len, frag->l4_hdr.ptr_needs_kfree);
	switch (frag->l4_hdr.proto) {
	case L4PROTO_TCP:
		tcp_header = frag_get_tcp_hdr(frag);
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
		udp_header = frag_get_udp_hdr(frag);
		pr_debug("		source port: %u\n", be16_to_cpu(udp_header->source));
		pr_debug("		destination port: %u\n", be16_to_cpu(udp_header->dest));
		pr_debug("		length: %u\n", be16_to_cpu(udp_header->len));
		pr_debug("		checksum: %u\n", udp_header->check);
		break;

	case L4PROTO_ICMP:
		/* too lazy */
		break;
	case L4PROTO_NONE:
		break;
	}

	pr_debug("Payload - length:%u kfree:%d\n", frag->payload.len, frag->payload.ptr_needs_kfree);
}

int pkt_alloc(struct packet **pkt_out)
{
	struct packet *pkt;

	pkt = kmem_cache_alloc(pkt_cache, GFP_ATOMIC);
	if (!pkt) {
		log_debug("Could not allocate a struct packet.");
		inc_stats(skb, IPSTATS_MIB_INDISCARDS);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&pkt->fragments);
	pkt->first_fragment = NULL;

	*pkt_out = pkt;
	return 0;
}

int pkt_create(struct fragment *frag, struct packet **pkt_out)
{
	int error;

	error = pkt_alloc(pkt_out);
	if (error)
		return error;

	pkt_add_frag(*pkt_out, frag);

	return 0;
}

void pkt_add_frag(struct packet *pkt, struct fragment *frag)
{
	list_add(&frag->list_hook, pkt->fragments.prev);
	if (frag->l4_hdr.proto != L4PROTO_NONE)
		pkt->first_fragment = frag;
}

int pkt_get_total_len_ipv6(struct packet *pkt, unsigned int *total_len)
{
	struct fragment *frag, *last_frag;
	u16 frag_offset;

	if (frag_is_fragmented(pkt->first_fragment)) {
		/* Find the last fragment. */
		last_frag = NULL;
		list_for_each_entry(frag, &pkt->fragments, list_hook) {
			if (!is_more_fragments_set_ipv6(frag_get_fragment_hdr(frag))) {
				last_frag = frag;
				break;
			}
		}

		/*
		 * This is unexpected because this function is only called after the database has already
		 * collected all of pkt's fragments.
		 */
		if (WARN(!last_frag, "IPv6 packet has no last fragment.")) {
			inc_stats(skb, IPSTATS_MIB_INDISCARDS);
			return -EINVAL;
		}

		/* Compute its offset. */
		frag_offset = get_fragment_offset_ipv6(frag_get_fragment_hdr(last_frag));
	} else {
		last_frag = pkt->first_fragment;
		frag_offset = 0;
	}

	*total_len = frag_offset + last_frag->l4_hdr.len + last_frag->payload.len;
	return 0;
}

int pkt_get_total_len_ipv4(struct packet *pkt, unsigned int *total_len)
{
	struct fragment *last_frag;
	u16 frag_offset;

	if (frag_is_fragmented(pkt->first_fragment)) {
		/* Find the last fragment. */
		last_frag = NULL;
		list_for_each_entry(last_frag, &pkt->fragments, list_hook) {
			if (!is_more_fragments_set_ipv4(frag_get_ipv4_hdr(last_frag)))
				break;
		}

		/*
		 * This is unexpected because this function is only called after the database has already
		 * collected all of pkt's fragments.
		 */
		if (WARN(!last_frag, "IPv4 packet has no last fragment.")) {
			inc_stats(skb, IPSTATS_MIB_INDISCARDS);
			return -EINVAL;
		}

		/* Compute its offset. */
		frag_offset = get_fragment_offset_ipv4(frag_get_ipv4_hdr(last_frag));
	} else {
		last_frag = pkt->first_fragment;
		frag_offset = 0;
	}

	*total_len = frag_offset + last_frag->l4_hdr.len + last_frag->payload.len;
	return 0;
}

void pkt_kfree(struct packet *pkt)
{
	struct fragment *frag;

	if (!pkt)
		return;

	while (!list_empty(&pkt->fragments)) {
		frag = pkt_get_first_frag(pkt);
		frag_kfree(frag);
	}

	kmem_cache_free(pkt_cache, pkt);
}
