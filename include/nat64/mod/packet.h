#ifndef _JOOL_MOD_PACKET_H
#define _JOOL_MOD_PACKET_H

/**
 * @file
 * Random skb-related functions.
 *
 * @author Alberto Leiva
 */

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

static inline bool is_first_fragment_ipv4(struct iphdr *hdr)
{
	return get_fragment_offset_ipv4(hdr) == 0;
}

static inline bool is_first_fragment_ipv6(struct frag_hdr *hdr)
{
	return hdr ? (get_fragment_offset_ipv6(hdr) == 0) : true;
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
	__u16 result = (df ? (1 << 14) : 0)
			| (mf ? (1 << 13) : 0)
			| (frag_offset >> 3); /* 3 bit shifts to the right == division by 8. */
	return cpu_to_be16(result);
}

/**
 * Returns the size in bytes of "hdr", including options.
 * skbless variant of tcp_hdrlen().
 */
static inline int tcp_hdr_len(struct tcphdr *hdr)
{
	return hdr->doff << 2;
}

/**
 * This structure is what Jool stores in control buffers.
 * Control buffers are reserved spaces in skbs where their current owners (ie. Jool) can store
 * whatever.
 *
 * If you're planning to change this structure, keep in mind its size cannot exceed
 * sizeof(skb->cb).
 */
struct jool_cb {
	/**
	 * Protocol of the layer-3 header of the packet.
	 * Yes, skb->proto has the same superpowers, but it's a little unreliable (it's not set in the
	 * Local Out chain, though that doesn't affect us ATM).
	 * Also this saves me a switch in skb_l3_proto() :p.
	 */
	__u8 l3_proto;
	/**
	 * Protocol of the layer-4 header of the packet. To the best of my knowledge, the kernel also
	 * uses skb->proto for this, but only on layer-4 code (of which Jool isn't).
	 * Skbs otherwise do not store a layer-4 identifier.
	 */
	__u8 l4_proto;
	/**
	 * Pointer to the packet's payload.
	 * Because skbs only store pointers to headers.
	 */
	void *payload;
	/**
	 * If the packet is IPv6 and has a fragment header, this points to it. Else, this holds NULL.
	 */
	struct frag_hdr *frag_hdr;
	/**
	 * If this is an incoming packet (as in, incoming to Jool), this points to the same packet.
	 * Otherwise (which includes hairpin packets), this points to the original (incoming) packet.
	 * Used by the ICMP wrapper because it needs to reply the original packet, not the one being
	 * translated. Also used by the packet queue.
	 */
	struct sk_buff *original_skb;
};

/**
 * Returns "skb"'s control buffer in Jool's format.
 * (jcb = Jool's control buffer.)
 */
static inline struct jool_cb *skb_jcb(struct sk_buff *skb)
{
	return (struct jool_cb *) skb->cb;
}

/**
 * Zeroizes "skb"'s control buffer.
 * The kernel will go nuts if you don't do this before you transfer "skb"'s ownership; most
 * citizens in the kernel assume everyone else cleans up their garbage.
 */
static inline void skb_clear_cb(struct sk_buff *skb)
{
	struct jool_cb *cb;
	cb = skb_jcb(skb);
	memset(cb, 0, sizeof(*cb));
}

/**
 * Initializes "skb"'s control buffer using the rest of the arguments.
 */
static inline void skb_set_jcb(struct sk_buff *skb, l3_protocol l3_proto, l4_protocol l4_proto,
		void *payload, struct frag_hdr *fraghdr, struct sk_buff *original_skb)
{
	struct jool_cb *cb = skb_jcb(skb);

	cb->l3_proto = l3_proto;
	cb->l4_proto = l4_proto;
	cb->payload = payload;
	cb->frag_hdr = fraghdr;
	cb->original_skb = original_skb;
}

/**
 * Returns "skb"'s layer-3 protocol in enum format.
 */
static inline l3_protocol skb_l3_proto(struct sk_buff *skb)
{
	return skb_jcb(skb)->l3_proto;
}

/**
 * Returns "skb"'s layer-4 protocol in enum format.
 */
static inline l4_protocol skb_l4_proto(struct sk_buff *skb)
{
	return skb_jcb(skb)->l4_proto;
}

/**
 * Returns a pointer to "skb"'s layer-4 payload.
 */
static inline void *skb_payload(struct sk_buff *skb)
{
	return skb_jcb(skb)->payload;
}

/**
 * Returns a pointer to "skb"'s fragment header, if it has one.
 */
static inline struct frag_hdr *skb_frag_hdr(struct sk_buff *skb)
{
	return skb_jcb(skb)->frag_hdr;
}

/**
 * Returns the packet Jool started with, which lead to the current "skb".
 */
static inline struct sk_buff *skb_original_skb(struct sk_buff *skb)
{
	return skb_jcb(skb)->original_skb;
}

/**
 * Fragments other than the one with no offset do not contain a layer-4 header.
 * If this returns false, you should not try to extract a layer-4 header from "skb".
 */
static inline bool skb_has_l4_hdr(struct sk_buff *skb)
{
	/*
	 * The kernel seems to do it this way, particularly when transport_header hasn't been set.
	 * I think it'd make more sense as payload != transport_header, but whatever.
	 */
	return skb_network_header(skb) != skb_transport_header(skb);
}

/**
 * Returns the length of "skb"'s layer-3 header, including options or extension headers.
 */
static inline int skb_l3hdr_len(struct sk_buff *skb)
{
	return skb_has_l4_hdr(skb)
			? (skb_transport_header(skb) - skb_network_header(skb))
			: (skb_payload(skb) - (void *) skb_network_header(skb));
}

/**
 * Returns the length of "skb"'s layer-4 header, including options.
 */
static inline int skb_l4hdr_len(struct sk_buff *skb)
{
	return skb_has_l4_hdr(skb)
			? (skb_payload(skb) - (void *) skb_transport_header(skb))
			: 0;
}

/**
 * Returns the length of "skb"'s layer-4 payload.
 */
static inline int skb_payload_len(struct sk_buff *skb)
{
	return skb->len - (skb_payload(skb) - (void *) skb_network_header(skb));
}

/**
 * Returns in "len" the length of the layer-3 payload of "skb".
 *
 * If "skb" is not fragmented, this is the length of the layer-4 header plus the length of the
 * actual payload.
 * If "skb" is fragmented, this is the length of the layer-4 header plus the length of the actual
 * payloads of every fragment.
 */
int skb_aggregate_ipv4_payload_len(struct sk_buff *skb, unsigned int *len);
int skb_aggregate_ipv6_payload_len(struct sk_buff *skb, unsigned int *len);
/**
 * @}
 */

/**
 * Fails if "hdr" is corrupted.
 *
 * @param length of the buffer "hdr" belongs to.
 * @param is_truncated whether the buffer "hdr" belongs to *might* be truncated, and this should
 *		not be considered a problem.
 * @param iterator this function will leave this iterator at the layer-3 payload of "hdr"'s buffer.
 */
int validate_ipv6_integrity(struct ipv6hdr *hdr, unsigned int len, bool is_truncated,
		struct hdr_iterator *iterator);
/**
 * Fails if "hdr" is corrupted.
 *
 * @param length of the buffer "hdr" belongs to.
 * @param is_truncated whether the buffer "hdr" belongs to *might* be truncated, and this should
 *		not be considered a problem.
 */
int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated);

/**
 * @{
 * Fails if the parameters describe an invalid respective layer-4 header.
 *
 * @param len length of the buffer the header belongs to.
 * @param l3_hdr_len length of the layer-3 headers of the buffer the header belongs to.
 */
int validate_lengths_tcp(unsigned int len, u16 l3_hdr_len, struct tcphdr *hdr);
int validate_lengths_udp(unsigned int len, u16 l3_hdr_len);
int validate_lengths_icmp6(unsigned int len, u16 l3_hdr_len);
int validate_lengths_icmp4(unsigned int len, u16 l3_hdr_len);
/**
 * @}
 */

/**
 * kfrees "skb". The point is, if "skb" is fragmented, it also kfrees the rest of the fragments.
 */
void kfree_skb_queued(struct sk_buff *skb);

/**
 * Initializes "skb"'s control buffer. It also validates "skb".
 */
int skb_init_cb_ipv6(struct sk_buff *skb);
int skb_init_cb_ipv4(struct sk_buff *skb);
/**
 * @}
 */

/**
 * Outputs "skb" in the log.
 */
void skb_print(struct sk_buff *skb);

/**
 * @{
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
/**
 * @}
 */

#endif /* _JOOL_MOD_PACKET_H */
