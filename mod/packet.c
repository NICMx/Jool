#include "nat64/mod/packet.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"


#define MIN_IPV6_HDR_LEN sizeof(struct ipv6hdr)
#define MIN_IPV4_HDR_LEN sizeof(struct iphdr)
#define MIN_TCP_HDR_LEN sizeof(struct tcphdr)
#define MIN_UDP_HDR_LEN sizeof(struct udphdr)
#define MIN_ICMP6_HDR_LEN sizeof(struct icmp6hdr)
#define MIN_ICMP4_HDR_LEN sizeof(struct icmphdr)


verdict frag_create_empty(struct fragment **out)
{
	struct fragment *frag;

	frag = kmalloc(sizeof(*frag), GFP_ATOMIC);
	if (!frag)
		return VER_DROP;

	memset(frag, 0, sizeof(*frag));
	INIT_LIST_HEAD(&frag->next);

	*out = frag;
	return VER_CONTINUE;
}

static verdict validate_lengths_tcp(struct sk_buff *skb, u16 l3_hdr_len)
{
	if (skb->len < l3_hdr_len + MIN_TCP_HDR_LEN) {
		log_debug("Packet is too small to contain a basic TCP header.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static verdict validate_lengths_udp(struct sk_buff *skb, u16 l3_hdr_len)
{
	if (skb->len < l3_hdr_len + MIN_UDP_HDR_LEN) {
		log_debug("Packet is too small to contain a UDP header.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static verdict validate_lengths_icmp6(struct sk_buff *skb, u16 l3_hdr_len)
{
	if (skb->len < l3_hdr_len + MIN_ICMP6_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv6 header.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

static verdict validate_lengths_icmp4(struct sk_buff *skb, u16 l3_hdr_len)
{
	if (skb->len < l3_hdr_len + MIN_ICMP4_HDR_LEN) {
		log_debug("Packet is too small to contain a ICMPv4 header.");
		return VER_DROP;
	}

	return VER_CONTINUE;
}

verdict validate_csum_icmp6(struct sk_buff *skb, int datagram_len)
{
	struct ipv6hdr *ip6_hdr = ipv6_hdr(skb);
	struct icmp6hdr *hdr = icmp6_hdr(skb);

	__sum16 tmp;
	__sum16 computed_csum;

	tmp = hdr->icmp6_cksum;
	hdr->icmp6_cksum = 0;
	computed_csum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr, datagram_len, NEXTHDR_ICMP,
			csum_partial(skb_transport_header(skb), datagram_len, 0));
	hdr->icmp6_cksum = tmp;

	if (tmp != computed_csum) {
		log_warning("Checksum doesn't match (protocol: %d). Expected: %x, actual: %x.",
				NEXTHDR_ICMP, computed_csum, tmp);
		return VER_DROP;
	}

	return VER_CONTINUE;
}

verdict validate_csum_icmp4(struct sk_buff *skb, int datagram_len)
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

static verdict validate_ipv6_integrity(struct sk_buff *skb, struct hdr_iterator *iterator)
{
	struct ipv6hdr *ip6_header;
	enum hdr_iterator_result result;

	ip6_header = ipv6_hdr(skb);

	/* (This is commented out because the hook has to do it anyway.)
	if (skb->len < MIN_IPV6_HDR_LEN) {
		log_debug("Packet is too small to contain a basic IPv6 header.");
		return VER_DROP;
	}
	*/
	if (skb->len != MIN_IPV6_HDR_LEN + be16_to_cpu(ip6_header->payload_len)) {
		log_debug("The socket buffer's length does not match the IPv6 header's payload length field.");
		return VER_DROP;
	}

	hdr_iterator_init(iterator, ip6_header);
	result = hdr_iterator_last(iterator);

	switch (result) {
	case HDR_ITERATOR_SUCCESS:
		log_crit(ERR_INVALID_ITERATOR, "Iterator reports there are headers beyond the payload.");
		return VER_DROP;
	case HDR_ITERATOR_END:
		return VER_CONTINUE;
	case HDR_ITERATOR_UNSUPPORTED:
		/* RFC 6146 section 5.1. */
		log_info("Packet contains an Authentication or ESP header, which I do not support.");
		return VER_DROP;
	case HDR_ITERATOR_OVERFLOW:
		log_warning("IPv6 extension header analysis ran past the end of the packet. "
				"Packet seems corrupted; ignoring.");
		return VER_DROP;
	default:
		log_crit(ERR_INVALID_ITERATOR, "Unknown header iterator result code: %d.", result);
		return VER_DROP;
	}
}

static verdict init_ipv6_l3_fields(struct fragment *frag, struct hdr_iterator *iterator)
{
	struct ipv6hdr *ip6_header = ipv6_hdr(frag->skb);

	frag->l3_hdr.proto = L3PROTO_IPV6;
	/* IPv6 header length = transport header offset - IPv6 header offset. */
	frag->l3_hdr.len = iterator->data - (void *) ip6_header;
	frag->l3_hdr.ptr = ip6_header;
	frag->l3_hdr.ptr_needs_kfree = false;

	return VER_CONTINUE;
}

static verdict init_ipv6_l4_fields(struct fragment *frag, struct hdr_iterator *iterator)
{
	struct ipv6hdr *ip6_header;
	struct frag_hdr *frag_header;

	ip6_header = ipv6_hdr(frag->skb);
	frag_header = get_extension_header(ip6_header, NEXTHDR_FRAGMENT);

	if (frag_header == NULL || get_fragment_offset_ipv6(frag_header) == 0) {
		verdict result;

		skb_set_transport_header(frag->skb, iterator->data - (void *) ip6_header);

 		switch (iterator->hdr_type) {
		case NEXTHDR_TCP:
			result = validate_lengths_tcp(frag->skb, frag->l3_hdr.len);
			if (result != VER_CONTINUE)
				return result;

			frag->l4_hdr.proto = L4PROTO_TCP;
			frag->l4_hdr.len = tcp_hdrlen(frag->skb);
			break;

		case NEXTHDR_UDP:
			result = validate_lengths_udp(frag->skb, frag->l3_hdr.len);
			if (result != VER_CONTINUE)
				return result;

			frag->l4_hdr.proto = L4PROTO_UDP;
			frag->l4_hdr.len = sizeof(struct udphdr);
			break;

		case NEXTHDR_ICMP:
			result = validate_lengths_icmp6(frag->skb, frag->l3_hdr.len);
			if (result != VER_CONTINUE)
				return result;

			frag->l4_hdr.proto = L4PROTO_ICMP;
			frag->l4_hdr.len = sizeof(struct icmp6hdr);
			break;

		default:
			log_warning("Unsupported layer 4 protocol: %d", iterator->hdr_type);
			return VER_DROP;
		}

		frag->l4_hdr.ptr = iterator->data;
	} else {
		frag->l4_hdr.proto = L4PROTO_NONE;
		frag->l4_hdr.len = 0;
		frag->l4_hdr.ptr = NULL;
	}

	frag->l4_hdr.ptr_needs_kfree = false;

	return VER_CONTINUE;
}

struct fragment *frag_create_ipv6(struct sk_buff *skb)
{
	struct fragment *frag;
	struct hdr_iterator iterator;

	if (validate_ipv6_integrity(skb, &iterator) != VER_CONTINUE)
		return NULL;

	frag = kmalloc(sizeof(*frag), GFP_ATOMIC);
	if (!frag) {
		log_warning("Cannot allocate a fragment structure.");
		return NULL;
	}
	frag->skb = skb;

	/* Layer 3 */
	if (init_ipv6_l3_fields(frag, &iterator) != VER_CONTINUE)
		goto error;

	/* Layer 4 */
	if (init_ipv6_l4_fields(frag, &iterator) != VER_CONTINUE)
		goto error;

	/* Payload */
	if (frag->l4_hdr.proto == L4PROTO_NONE) {
		frag->payload.len = iterator.limit - iterator.data;
		frag->payload.ptr = iterator.data;
	} else {
		frag->payload.len = skb->len - frag->l3_hdr.len - frag->l4_hdr.len;
		frag->payload.ptr = frag->l4_hdr.ptr + frag->l4_hdr.len;
	}
	frag->payload.ptr_needs_kfree = false;

	/* List */
	INIT_LIST_HEAD(&frag->next);

	return frag;

error:
	kfree(frag);
	return NULL;
}

static verdict validate_ipv4_integrity(struct sk_buff *skb)
{
	struct iphdr *ip4_hdr = ip_hdr(skb);
	u16 ip4_hdr_len;

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

	return VER_CONTINUE;
}

static verdict init_ipv4_l3_hdr(struct fragment *frag)
{
	struct iphdr *ipv4_header = ip_hdr(frag->skb);

	frag->l3_hdr.proto = L3PROTO_IPV4;
	frag->l3_hdr.len = ipv4_header->ihl << 2;
	frag->l3_hdr.ptr = ipv4_header;
	frag->l3_hdr.ptr_needs_kfree = false;

	return VER_CONTINUE;
}

static verdict init_ipv4_l3_payload(struct fragment *frag)
{
	struct iphdr *ipv4_header = ip_hdr(frag->skb);
	u16 fragment_offset;
	verdict result;

	fragment_offset = get_fragment_offset_ipv4(ipv4_header);
	if (fragment_offset == 0) {
		skb_set_transport_header(frag->skb, frag->l3_hdr.len);

		switch (ipv4_header->protocol) {
		case IPPROTO_TCP:
			result = validate_lengths_tcp(frag->skb, frag->l3_hdr.len);
			if (result != VER_CONTINUE)
				return result;

			frag->l4_hdr.proto = L4PROTO_TCP;
			frag->l4_hdr.len = tcp_hdrlen(frag->skb);
			break;

		case IPPROTO_UDP:
			result = validate_lengths_udp(frag->skb, frag->l3_hdr.len);
			if (result != VER_CONTINUE)
				return result;

			frag->l4_hdr.proto = L4PROTO_UDP;
			frag->l4_hdr.len = sizeof(struct udphdr);
			break;

		case IPPROTO_ICMP:
			result = validate_lengths_icmp4(frag->skb, frag->l3_hdr.len);
			if (result != VER_CONTINUE)
				return result;

			frag->l4_hdr.proto = L4PROTO_ICMP;
			frag->l4_hdr.len = sizeof(struct icmphdr);
			break;

		default:
			log_warning("Unsupported layer 4 protocol: %d", ipv4_header->protocol);
			return VER_DROP;
		}
		frag->l4_hdr.ptr = frag->l3_hdr.ptr + frag->l3_hdr.len;
		frag->payload.ptr = frag->l4_hdr.ptr + frag->l4_hdr.len;

	} else {
		frag->l4_hdr.proto = L4PROTO_NONE;
		frag->l4_hdr.len = 0;
		frag->l4_hdr.ptr = NULL;
		frag->payload.ptr = frag->l3_hdr.ptr + frag->l3_hdr.len;
	}

	frag->l4_hdr.ptr_needs_kfree = false;
	frag->payload.len = frag->skb->len - frag->l3_hdr.len - frag->l4_hdr.len;
	frag->payload.ptr_needs_kfree = false;

	return VER_CONTINUE;
}

struct fragment *frag_create_ipv4(struct sk_buff *skb)
{
	struct fragment *frag;

	if (validate_ipv4_integrity(skb) != VER_CONTINUE)
		return NULL;

	frag = kmalloc(sizeof(*frag), GFP_ATOMIC);
	if (!frag) {
		log_warning("Cannot allocate a fragment structure.");
		return NULL;
	}
	frag->skb = skb;

	if (init_ipv4_l3_hdr(frag) != VER_CONTINUE)
		goto error;
	if (init_ipv4_l3_payload(frag) != VER_CONTINUE)
		goto error;
	INIT_LIST_HEAD(&frag->next);

	return frag;

error:
	kfree(frag);
	return NULL;
}

/**
 * Joins frag.l3_hdr, frag.l4_hdr and frag.payload into a single packet, placing the result in
 * frag.skb.
 *
 * Assumes that frag.skb is NULL (Hence, frag->*.ptr_belongs_to_skb are false).
 */
verdict frag_create_skb(struct fragment *frag)
{
	struct sk_buff *new_skb;
	__u16 head_room = 0, tail_room = 0;
	bool has_l4_hdr;

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

	has_l4_hdr = (frag->l4_hdr.ptr != NULL);

	skb_reserve(new_skb, head_room + LL_MAX_HEADER);
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
		return VER_DROP;
	}

	return VER_CONTINUE;
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

struct packet *pkt_create(struct fragment *frag)
{
	struct packet *pkt;

	pkt = kmalloc(sizeof(*pkt), GFP_ATOMIC);
	if (!pkt) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate a packet.");
		return NULL;
	}

	INIT_LIST_HEAD(&pkt->fragments);
	pkt_add_frag(pkt, frag);

	return pkt;
}

void pkt_add_frag(struct packet *pkt, struct fragment *frag)
{
	list_add(&frag->next, pkt->fragments.prev);
	if (frag->l4_hdr.proto != L4PROTO_NONE)
		pkt->first_fragment = frag;
}

void pkt_kfree(struct packet *pkt, bool free_pkt)
{
	if (!pkt)
		return;

	while (!list_empty(&pkt->fragments)) {
		/* pkt->fragment.next is the first element of the list. */
		struct fragment *frag = list_entry(pkt->fragments.next, struct fragment, next);
		frag_kfree(frag);
	}

	if (free_pkt)
		kfree(pkt);
}
