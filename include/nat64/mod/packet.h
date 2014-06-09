#ifndef _NF_NAT64_PACKET_H
#define _NF_NAT64_PACKET_H

#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/tcp.h>

#include "nat64/comm/types.h"
#include "nat64/mod/ipv6_hdr_iterator.h"


/** Returns a hack-free version of the 'Traffic class' field from the "hdr" IPv6 header. */
static inline __u8 get_traffic_class(struct ipv6hdr *hdr)
{
	__u8 upper_bits = hdr->priority;
	__u8 lower_bits = hdr->flow_lbl[0] >> 4;
	return (upper_bits << 4) | lower_bits;
}

/**
 * Returns a big endian (but otherwise hack-free) version of the 'Flow label' field from the "hdr"
 * IPv6 header.
 */
static inline __be32 get_flow_label(struct ipv6hdr *hdr)
{
	return (*(__be32 *) hdr) & IPV6_FLOWLABEL_MASK;
}

/** Returns true if the DF flag from the "hdr" IPv4 header is set, false otherwise. */
static inline bool is_dont_fragment_set(struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	return (frag_off & IP_DF) >> 14;
}

/** Returns true if the MF flag from the "hdr" IPv6 header is set, false otherwise. */
static inline bool is_more_fragments_set_ipv6(struct frag_hdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	return (frag_off & IP6_MF);
}

/** Returns true if the MF flag from the "hdr" IPv4 header is set, false otherwise. */
static inline bool is_more_fragments_set_ipv4(struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	return (frag_off & IP_MF) >> 13;
}

/** Returns a hack-free version of the 'Fragment offset' field from the "hdr" fragment header. */
static inline __u16 get_fragment_offset_ipv6(struct frag_hdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & 0xFFF8;
}

/** Returns a hack-free version of the 'Fragment offset' field from the "hdr" IPv4 header. */
static inline __u16 get_fragment_offset_ipv4(struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	/* 3 bit shifts to the left == multiplication by 8. */
	return (frag_off & IP_OFFSET) << 3;
}

/**
 * frag_hdr.frag_off is actually a combination of the 'More fragments' flag and the
 * 'Fragment offset' field. This function is a one-liner for creating a settable frag_off.
 * Note that fragment offset is measured in units of eight-byte blocks. That means that you want
 * "frag_offset" to be a multiple of 8 if you want your fragmentation to work properly.
 */
static inline __be16 build_ipv6_frag_off_field(__u16 frag_offset, bool mf)
{
	__u16 result = (frag_offset & 0xFFF8)
			| (mf << 0);
	return cpu_to_be16(result);
}

/**
 * iphdr.frag_off is actually a combination of the DF flag, the MF flag, and the 'Fragment offset'
 * field. This function is a one-liner for creating a settable frag_off.
 * Note that fragment offset is measured in units of eight-byte blocks. That means that you want
 * "frag_offset" to be a multiple of 8 if you want your fragmentation to work properly.
 */
static inline __be16 build_ipv4_frag_off_field(bool df, bool mf, __u16 frag_offset)
{
	__u16 result = (df << 14)
			| (mf << 13)
			| (frag_offset >> 3); /* 3 bit shifts to the right == division by 8. */
	return cpu_to_be16(result);
}

static inline int tcp_hdr_len(struct tcphdr *hdr)
{
	return hdr->doff << 2;
}


struct jool_cb {
	__u8 l3_proto;
	__u8 l4_proto;
	void *payload;
	struct sk_buff *original_skb;
};

static inline struct jool_cb *skb_jcb(struct sk_buff *skb)
{
	return (struct jool_cb *) skb->cb;
}

static inline void skb_clear_cb(struct sk_buff *skb)
{
	struct jool_cb *cb;
	cb = skb_jcb(skb);
	memset(cb, 0, sizeof(*cb));
}

static inline void skb_set_jcb(struct sk_buff *skb, l3_protocol l3_proto, l4_protocol l4_proto,
		void *payload, struct sk_buff *original_skb)
{
	struct jool_cb *cb = skb_jcb(skb);

	cb->l3_proto = l3_proto;
	cb->l4_proto = l4_proto;
	cb->payload = payload;
	cb->original_skb = original_skb;
}

static inline l3_protocol skb_l3_proto(struct sk_buff *skb)
{
	return skb_jcb(skb)->l3_proto;
}

static inline l4_protocol skb_l4_proto(struct sk_buff *skb)
{
	return skb_jcb(skb)->l4_proto;
}

static inline void *skb_payload(struct sk_buff *skb)
{
	return skb_jcb(skb)->payload;
}

static inline struct sk_buff *skb_original_skb(struct sk_buff *skb)
{
	return skb_jcb(skb)->original_skb;
}

static inline bool has_l4_hdr(struct sk_buff *skb)
{
	return skb_network_header(skb) != skb_transport_header(skb);
}

static inline int skb_l3hdr_len(struct sk_buff *skb)
{
	return has_l4_hdr(skb)
			? (skb_transport_header(skb) - skb_network_header(skb))
			: (skb_payload(skb) - (void *) skb_network_header(skb));
}

static inline int skb_l4hdr_len(struct sk_buff *skb)
{
	return has_l4_hdr(skb)
			? (skb_payload(skb) - (void *) skb_transport_header(skb))
			: 0;
}

static inline int skb_payload_len(struct sk_buff *skb)
{
	return skb->len - (skb_payload(skb) - (void *) skb_network_header(skb));
}

int validate_ipv6_integrity(struct ipv6hdr *hdr, unsigned int len, bool is_truncated,
		struct hdr_iterator *iterator);
int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated);

int validate_lengths_tcp(unsigned int len, u16 l3_hdr_len, struct tcphdr *hdr);
int validate_lengths_udp(unsigned int len, u16 l3_hdr_len);
int validate_lengths_icmp6(unsigned int len, u16 l3_hdr_len);
int validate_lengths_icmp4(unsigned int len, u16 l3_hdr_len);

void kfree_skb_queued(struct sk_buff *skb);
int skb_init_cb_ipv6(struct sk_buff *skb);
int skb_init_cb_ipv4(struct sk_buff *skb);
void skb_print(struct sk_buff *skb);

/**
 * These functions adjust skb's layer-4 checksums if neccesary.
 *
 * In an ideal world, Jool would not have to worry about checksums because it's really just a
 * pseudo-routing, mostly layer-3 device; layer-4 checksum verification is a task best left to
 * endpoints. However, in reality transport checksums are usually affected by the layer-3 protocol,
 * so we need to work around them.
 *
 * Thanks to these functions, the rest of Jool can assume the incoming layer-4 checksum is valid in
 * all circumstances:
 * - If skb is a TCP, ICMP info or a checksum-featuring UDP packet, these functions do nothing
 *   because the translation mangling is going to be simple enough that Jool will be able to update
 *   (rather than recompute) the existing checksum. Any existing corruption will still be reflected
 *   in the checksum and the destination node will be able to tell.
 * - If pkt is a ICMP error, then these functions will drop the packet if its checksum doesn't
 *   match. This is because the translation might change the packet considerably, so Jool will have
 *   to recompute the checksum completely, and we shouldn't assign a correct checksum to a
 *   corrupted packet.
 * - If pkt is a IPv4 zero-checksum UDP packet, then these functions will compute and assign its
 *   checksum. If there's any corruption, the destination node will have to bear it. This behavior
 *   is mandated by RFC 6146 section 3.4.
 */
int fix_checksums_ipv6(struct sk_buff *skb);
int fix_checksums_ipv4(struct sk_buff *skb);


#endif /* _NF_NAT64_PACKET_H */
