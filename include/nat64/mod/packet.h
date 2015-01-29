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

/**
 * @{
 * Does "hdr" belong to the fragment whose fragment offset is zero?
 * A non-fragmented packet is also considered a first fragment.
 */
static inline bool is_first_fragment_ipv4(struct iphdr *hdr)
{
	return get_fragment_offset_ipv4(hdr) == 0;
}

static inline bool is_first_fragment_ipv6(struct frag_hdr *hdr)
{
	return hdr ? (get_fragment_offset_ipv6(hdr) == 0) : true;
}
/**
 * @}
 */

/**
 * @{
 * Is "hdr"'s packet a fragment?
 */
static inline bool is_fragmented_ipv4(struct iphdr *hdr)
{
	return (get_fragment_offset_ipv4(hdr) != 0) || is_more_fragments_set_ipv4(hdr);
}

static inline bool is_fragmented_ipv6(struct frag_hdr *hdr)
{
	return hdr && ((get_fragment_offset_ipv6(hdr) != 0) || is_more_fragments_set_ipv6(hdr));
}
/**
 * @}
 */

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
static inline unsigned int tcp_hdr_len(struct tcphdr *hdr)
{
	return hdr->doff << 2;
}

/**
 * This structure is what Jool stores in control buffers.
 * Control buffers are reserved spaces in skbs where their current owners (ie. Jool) can store
 * whatever.
 *
 * I'm assuming skbs Jool receive are supposed to have clean control buffers, and therefore there's
 * no problem with the existence of this structure. Though common sense dictates any Netfilter
 * module should not have to worry about leftover CB garbage, I do not see any confirmation
 * (formal or otherwise) of this anywhere. Any objections?
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
#ifdef BENCHMARK
	/**
	 * Log the time in epoch when this skb arrives to jool. For benchmark purpouse.
	 */
	struct timespec start_time;
#endif
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
#ifdef BENCHMARK
	cb->start_time = skb_jcb(original_skb)->start_time;
#endif
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
	return skb_transport_header(skb) != skb_payload(skb);
}

/**
 * Returns the length of "skb"'s layer-3 header, including options or extension headers.
 */
static inline unsigned int skb_l3hdr_len(struct sk_buff *skb)
{
	return skb_transport_header(skb) - skb_network_header(skb);
}

/**
 * Returns the length of "skb"'s layer-4 header, including options.
 * Returns zero if skb has no transport header.
 */
static inline unsigned int skb_l4hdr_len(struct sk_buff *skb)
{
	return skb_payload(skb) - (void *) skb_transport_header(skb);
}

/**
 * Returns the length of "skb"'s layer-4 payload.
 */
static inline unsigned int skb_payload_len(struct sk_buff *skb)
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
 * @param len length of the buffer "hdr" belongs to.
 * @param is_truncated whether the payload of "hdr"'s buffer *might* be truncated, and this should
 *		not be considered a problem (validation will still fail if the buffer does not contain
 *		enough l3 and l4 headers).
 * @param iterator this function will leave this iterator at the layer-3 payload of "hdr"'s buffer.
 */
int validate_ipv6_integrity(struct ipv6hdr *hdr, unsigned int len, bool is_truncated,
		struct hdr_iterator *iterator, int *field);
/**
 * Fails if "hdr" is corrupted.
 *
 * @param len length of the buffer "hdr" belongs to.
 * @param is_truncated whether the payload of "hdr"'s buffer *might* be truncated, and this should
 *		not be considered a problem (validation will still fail if the buffer does not contain
 *		enough l3 and l4 headers).
 * @param is_inner when the "hdr" is part of a inner packet, we don't need to validate the checksum
 * 		field
 */
int validate_ipv4_integrity(struct iphdr *hdr, unsigned int len, bool is_truncated, int *field,
		bool is_inner);

/**
 * @{
 * Fails if the parameters describe an invalid respective layer-4 header.
 *
 * @param len length of the buffer the header belongs to.
 * @param l3_hdr_len length of the layer-3 headers of the buffer the header belongs to.
 */
int validate_lengths_tcp(unsigned int len, unsigned int l3_hdr_len, struct tcphdr *hdr);
int validate_lengths_udp(unsigned int len, unsigned int l3_hdr_len);
int validate_lengths_icmp6(unsigned int len, unsigned int l3_hdr_len);
int validate_lengths_icmp4(unsigned int len, unsigned int l3_hdr_len);
/**
 * @}
 */

/**
 * kfrees "skb". The point is, if "skb" is fragmented, it also kfrees the rest of the fragments.
 */
void kfree_skb_queued(struct sk_buff *skb);

/**
 * Returns "true" if "icmp_type" is defined by RFC 792 to contain a subpacket as payload.
 */
bool icmp4_has_inner_packet(__u8 icmp_type);

/**
 * Returns "true" if "icmp6_type" is defined by RFC 4443 to contain a subpacket as payload.
 */
bool icmpv6_has_inner_packet(__u8 icmp6_type);

/**
 * Initializes "skb"'s control buffer. It also validates "skb".
 *
 * After this function, code can assume:
 * - skb contains full l3 and l4 headers. In particular, the header continuity makes sense (eg.
 * you won't find a UDP header after a NEXTHDR_TCP). Inner l3 and l4 headers (in ICMP errors) are
 * also validated (except inner TCP options, which are just considered payload at this point).
 * - skb isn't truncated (though inner packets might).
 * - The cb functions above can now be used on skb.
 * - The length fields in the headers can be relied upon.
 *
 * Healthy layer 4 checksums are not guaranteed, but that's not an issue since this kind of
 * corruption should be translated along (see validate_icmp6_csum()).
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
 * Drops "skb" if it is an ICMP error packet and its l4-checksum doesn't match.
 *
 * Because IP-based checksums are updatable, Jool normally doesn't have to worry if a packet has a
 * bogus layer-4 checksum. It simply translates the packet and updates the checksum with these
 * changes. If there's a problem, it will still be reflected in the checksum and the target node
 * will drop it normally.
 *
 * That is, except for ICMP errors, whose translation is more nontrivial than usual due to their
 * inner packets. For these cases, Jool will recompute the checksum from scratch, and we should not
 * assign correct checksums to corrupted packets, so we need to validate them first.
 */
int validate_icmp6_csum(struct sk_buff *skb);
int validate_icmp4_csum(struct sk_buff *skb);
/**
 * @}
 */

#endif /* _JOOL_MOD_PACKET_H */
