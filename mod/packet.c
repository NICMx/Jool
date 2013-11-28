#include "nat64/mod/packet.h"

#include <net/icmp.h>

#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"


#define MIN_IPV6_HDR_LEN sizeof(struct ipv6hdr)
#define MIN_IPV4_HDR_LEN sizeof(struct iphdr)
#define MIN_TCP_HDR_LEN sizeof(struct tcphdr)
#define MIN_UDP_HDR_LEN sizeof(struct udphdr)
#define MIN_ICMP6_HDR_LEN sizeof(struct icmp6hdr)
#define MIN_ICMP4_HDR_LEN sizeof(struct icmphdr)


int frag_create_empty(struct fragment **out)
{
	struct fragment *frag;

	frag = kmalloc(sizeof(*frag), GFP_ATOMIC);
	if (!frag)
		return -ENOMEM;

	memset(frag, 0, sizeof(*frag));
	INIT_LIST_HEAD(&frag->next);

	*out = frag;
	return 0;
}

int frag_create_from_skb(struct sk_buff *skb, struct fragment **frag)
{
	int error;

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		error = frag_create_from_buffer_ipv4(skb_network_header(skb), skb->len, false, frag, skb);
		break;
	case ETH_P_IPV6:
		error = frag_create_from_buffer_ipv6(skb_network_header(skb), skb->len, false, frag, skb);
		break;
	default:
		log_err(ERR_L3PROTO, "Unsupported network protocol: %u", ntohs(skb->protocol));
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
		return -EINVAL;
	}

	return 0;
}

static int validate_lengths_udp(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_UDP_HDR_LEN) {
		log_debug("Packet is too small to contain a UDP header.");
		return -EINVAL;
	}

	return 0;
}

static int validate_lengths_icmp6(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP6_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv6 header.");
		return -EINVAL;
	}

	return 0;
}

static int validate_lengths_icmp4(unsigned int len, u16 l3_hdr_len)
{
	if (len < l3_hdr_len + MIN_ICMP4_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv4 header.");
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
		log_crit(ERR_INVALID_ITERATOR, "Iterator reports there are headers beyond the payload.");
		break;
	case HDR_ITERATOR_END:
		return 0;
	case HDR_ITERATOR_UNSUPPORTED:
		/* RFC 6146 section 5.1. */
		log_info("Packet contains an Authentication or ESP header, which I do not support.");
		break;
	case HDR_ITERATOR_OVERFLOW:
		log_warning("IPv6 extension header analysis ran past the end of the packet. "
				"Packet seems corrupted; ignoring.");
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
		struct hdr_iterator *iterator, struct sk_buff *skb)
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
			log_warning("Unsupported layer 4 protocol: %d", iterator->hdr_type);
			if (skb != NULL)
				icmpv6_send(frag->skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0);
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

	frag = kmalloc(sizeof(*frag), GFP_ATOMIC);
	if (!frag) {
		log_warning("Cannot allocate a fragment structure.");
		return -ENOMEM;
	}

	frag->skb = NULL;
	frag->dst = NULL;
	error = init_ipv6_l3_hdr(frag, hdr, &iterator);
	if (error)
		goto fail;
	error = init_ipv6_l3_payload(frag, hdr, len, &iterator, skb);
	if (error)
		goto fail;
	INIT_LIST_HEAD(&frag->next);

	*out_frag = frag;
	return 0;

fail:
	kfree(frag);
	return error;
}

static int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated)
{
	u16 ip4_hdr_len;

	if (len < MIN_IPV4_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IP header.");
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

static int init_ipv4_l3_hdr(struct fragment *frag, struct iphdr *hdr)
{
	frag->l3_hdr.proto = L3PROTO_IPV4;
	frag->l3_hdr.len = 4 * hdr->ihl;
	frag->l3_hdr.ptr = hdr;
	frag->l3_hdr.ptr_needs_kfree = false;

	return 0;
}

static int init_ipv4_l3_payload(struct fragment *frag, struct iphdr *hdr4, unsigned int len,
		struct sk_buff *skb)
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
			log_warning("Unsupported layer 4 protocol: %d", hdr4->protocol);
			if (skb != NULL)
				icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, 0);
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

	frag = kmalloc(sizeof(*frag), GFP_ATOMIC);
	if (!frag) {
		log_warning("Cannot allocate a fragment structure.");
		return -ENOMEM;
	}

	frag->skb = NULL;
	frag->dst = NULL;
	error = init_ipv4_l3_hdr(frag, hdr);
	if (error)
		goto fail;
	error = init_ipv4_l3_payload(frag, hdr, len, skb);
	if (error)
		goto fail;
	INIT_LIST_HEAD(&frag->next);

	*out_frag = frag;
	return 0;

fail:
	kfree(frag);
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
		log_err(ERR_ALLOC_FAILED, "New packet allocation failed.");
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
	default:
		log_err(ERR_L3PROTO, "Invalid protocol type: %u", frag->l3_hdr.proto);
		return -EINVAL;
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
	if (frag->skb)
		kfree_skb(frag->skb);
	if (frag->l3_hdr.ptr_needs_kfree)
		kfree(frag->l3_hdr.ptr);
	if (frag->l4_hdr.ptr_needs_kfree)
		kfree(frag->l4_hdr.ptr);
	if (frag->payload.ptr_needs_kfree)
		kfree(frag->payload.ptr);

	list_del(&frag->next);

	kfree(frag);
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
		log_info("(null)");
		return;
	}

	log_info("Layer 3 - proto:%s length:%u kfree:%d", l3proto_to_string(frag->l3_hdr.proto),
			frag->l3_hdr.len, frag->l3_hdr.ptr_needs_kfree);
	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV6:
		hdr6 = frag_get_ipv6_hdr(frag);
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
		hdr4 = frag_get_ipv4_hdr(frag);
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

	log_info("Layer 4 - proto:%s length:%u kfree:%d", l4proto_to_string(frag->l4_hdr.proto),
			frag->l4_hdr.len, frag->l4_hdr.ptr_needs_kfree);
	switch (frag->l4_hdr.proto) {
	case L4PROTO_TCP:
		tcp_header = frag_get_tcp_hdr(frag);
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
		udp_header = frag_get_udp_hdr(frag);
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

	log_info("Payload - length:%u kfree:%d", frag->payload.len, frag->payload.ptr_needs_kfree);
}

int pkt_create(struct fragment *frag, struct packet **pkt_out)
{
	struct packet *pkt;

	pkt = kmalloc(sizeof(*pkt), GFP_ATOMIC);
	if (!pkt) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate a packet.");
		return -ENOMEM;
	}

	pkt_init(pkt, frag);

	*pkt_out = pkt;
	return 0;
}

void pkt_init(struct packet *pkt, struct fragment *frag)
{
	INIT_LIST_HEAD(&pkt->fragments);
	pkt->first_fragment = NULL;
	pkt_add_frag(pkt, frag);
}

void pkt_add_frag(struct packet *pkt, struct fragment *frag)
{
	list_add(&frag->next, pkt->fragments.prev);
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
		list_for_each_entry(frag, &pkt->fragments, next) {
			if (!is_more_fragments_set_ipv6(frag_get_fragment_hdr(frag))) {
				last_frag = frag;
				break;
			}
		}
		if (!last_frag) {
			log_crit(ERR_UNKNOWN_ERROR, "IPv6 packet has no last fragment.");
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
		list_for_each_entry(last_frag, &pkt->fragments, next) {
			if (!is_more_fragments_set_ipv4(frag_get_ipv4_hdr(last_frag)))
				break;
		}
		if (!last_frag) {
			log_crit(ERR_UNKNOWN_ERROR, "IPv4 packet has no last fragment.");
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

void pkt_kfree(struct packet *pkt, bool free_pkt)
{
	struct fragment *frag;

	if (!pkt)
		return;

	while (!list_empty(&pkt->fragments)) {
		frag = pkt_get_first_frag(pkt);
		frag_kfree(frag);
	}

	if (free_pkt)
		kfree(pkt);
}
