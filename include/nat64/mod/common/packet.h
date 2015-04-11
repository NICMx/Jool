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
#include <linux/icmp.h>

#include "nat64/mod/common/types.h"


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

/** Returns IP_DF if the DF flag from the "hdr" IPv4 header is set, 0 otherwise. */
static inline __u16 is_dont_fragment_set(struct iphdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP_DF;
}

/** Returns IP6_MF if the MF flag from the "hdr" IPv6 header is set, 0 otherwise. */
static inline __u16 is_more_fragments_set_ipv6(struct frag_hdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP6_MF;
}

/** Returns IP_MF if the MF flag from the "hdr" IPv4 header is set, 0 otherwise. */
static inline __u16 is_more_fragments_set_ipv4(struct iphdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP_MF;
}

/** Returns a hack-free version of the 'Fragment offset' field from the "hdr" fragment header. */
static inline __u16 get_fragment_offset_ipv6(struct frag_hdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & 0xFFF8U;
}

/** Returns a hack-free version of the 'Fragment offset' field from the "hdr" IPv4 header. */
static inline __u16 get_fragment_offset_ipv4(struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	/* 3 bit shifts to the left == multiplication by 8. */
	return (frag_off & IP_OFFSET) << 3;
}

/**
 * Pretends skb's IPv6 header has a "total length" field and returns its value.
 * This function exists because turning "payload length" into "total length" by hand takes almost a
 * full line by itself, which forces us to break lines.
 */
static inline unsigned int get_tot_len_ipv6(struct sk_buff *skb)
{
	return sizeof(struct ipv6hdr) + be16_to_cpu(ipv6_hdr(skb)->payload_len);
}

/**
 * @{
 * Does "hdr" belong to the fragment whose fragment offset is zero?
 * A non-fragmented packet is also considered a first fragment.
 */
static inline bool is_first_frag4(struct iphdr *hdr)
{
	return get_fragment_offset_ipv4(hdr) == 0;
}

static inline bool is_first_frag6(struct frag_hdr *hdr)
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
static inline __be16 build_ipv6_frag_off_field(__u16 frag_offset, __u16 mf)
{
	__u16 result = (frag_offset & 0xFFF8U) | (mf ? 1U : 0U);
	return cpu_to_be16(result);
}

/**
 * iphdr.frag_off is actually a combination of the DF flag, the MF flag, and the 'Fragment offset'
 * field. This function is a one-liner for creating a settable frag_off.
 * Note that fragment offset is measured in units of eight-byte blocks. That means that you want
 * "frag_offset" to be a multiple of 8 if you want your fragmentation to work properly.
 */
static inline __be16 build_ipv4_frag_off_field(bool df, __u16 mf, __u16 frag_offset)
{
	__u16 result = (df ? (1U << 14) : 0)
			| (mf ? (1U << 13) : 0)
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
 * We need to store packet metadata, so we encapsulate sk_buffs into this.
 *
 * Do **not** use control buffers (skb->cb) for this purpose. The kernel is known to misbehave and
 * store information there which we should not override.
 */
struct packet {
	struct sk_buff *skb;

	/**
	 * Protocol of the layer-3 header of the packet.
	 * Yes, skb->proto has the same superpowers, but it's a little unreliable (it's not set in the
	 * Local Out chain).
	 * Also this spares me a switch in pkt_l3_proto() :p.
	 */
	enum l3_protocol l3_proto;
	/**
	 * Protocol of the layer-4 header of the packet. To the best of my knowledge, the kernel also
	 * uses skb->proto for this, but only on layer-4 code (of which Jool isn't).
	 * Skbs otherwise do not store a layer-4 identifier.
	 */
	enum l4_protocol l4_proto;
	/**
	 * Is this a subpacket, contained in an ICMP error? (used by the ttp module.)
	 */
	bool is_inner;

	struct frag_hdr *hdr_frag;
	/**
	 * Pointer to the packet's payload.
	 * Because skbs only store pointers to headers.
	 *
	 * Sometimes the kernel seems to use skb->data for this. It would be troublesome if we did the
	 * same, however, since functions such as icmp_send() fail early when skb->data is after the
	 * layer-3 header.
	 *
	 * Note, the payload can be paged. Do not dereference carelessly.
	 */
	void *payload;
	/**
	 * If this is an incoming packet (as in, incoming to Jool), this points to the same packet.
	 * Otherwise (which includes hairpin packets), this points to the original (incoming) packet.
	 * Used by the ICMP wrapper because it needs to reply the original packet, not the one being
	 * translated. Also used by the packet queue.
	 */
	struct packet *original_pkt;

#ifdef BENCHMARK
	/**
	 * Log the time in epoch when this skb arrives to jool. For benchmark purposes.
	 */
	struct timespec start_time;
#endif
};

/**
 * Initializes "pkt" using the rest of the arguments.
 */
static inline void pkt_fill(struct packet *pkt, struct sk_buff *skb,
		l3_protocol l3_proto, l4_protocol l4_proto,
		struct frag_hdr *hdr_frag, void *payload, struct packet *original_pkt)
{
	pkt->skb = skb;
	pkt->l3_proto = l3_proto;
	pkt->l4_proto = l4_proto;
	pkt->is_inner = 0;
	pkt->hdr_frag = hdr_frag;
	pkt->payload = payload;
	pkt->original_pkt = original_pkt;
#ifdef BENCHMARK
	pkt->start_time = original_pkt->start_time;
#endif
}

/**
 * Returns "skb"'s layer-3 protocol in enum format.
 */
static inline l3_protocol pkt_l3_proto(const struct packet *pkt)
{
	return pkt->l3_proto;
}

static inline struct iphdr *pkt_ip4_hdr(const struct packet *pkt)
{
	return ip_hdr(pkt->skb);
}

static inline struct ipv6hdr *pkt_ip6_hdr(const struct packet *pkt)
{
	return ipv6_hdr(pkt->skb);
}

/**
 * Returns "skb"'s layer-4 protocol in enum format.
 */
static inline l4_protocol pkt_l4_proto(const struct packet *pkt)
{
	return pkt->l4_proto;
}

static inline struct udphdr *pkt_udp_hdr(const struct packet *pkt)
{
	return udp_hdr(pkt->skb);
}

static inline struct tcphdr *pkt_tcp_hdr(const struct packet *pkt)
{
	return tcp_hdr(pkt->skb);
}

static inline struct icmphdr *pkt_icmp4_hdr(const struct packet *pkt)
{
	return icmp_hdr(pkt->skb);
}

static inline struct icmp6hdr *pkt_icmp6_hdr(const struct packet *pkt)
{
	return icmp6_hdr(pkt->skb);
}

static inline struct frag_hdr *pkt_frag_hdr(const struct packet *pkt)
{
	return pkt->hdr_frag;
}

static inline void *pkt_payload(const struct packet *pkt)
{
	return pkt->payload;
}

static inline bool pkt_is_inner(const struct packet *pkt)
{
	return pkt->is_inner;
}

static inline bool pkt_is_outer(const struct packet *pkt)
{
	return !pkt_is_inner(pkt);
}

static inline bool pkt_is_fragment(const struct packet *pkt)
{
	return skb_shinfo(pkt->skb)->frag_list ? true : false;
}

static inline int pkt_payload_offset(const struct packet *pkt)
{
	/*
	 * It seems like the the network header functions are cancelling each other.
	 * This is *NOT* reduntant!
	 * The point is to make the offset's reference the same as the network header's
	 * (whatever it is).
	 */
	return skb_network_offset(pkt->skb) + (pkt_payload(pkt) - (void *) skb_network_header(pkt->skb));
}

/**
 * Returns the packet Jool started with, which lead to the current "skb".
 */
static inline struct packet *pkt_original_pkt(const struct packet *pkt)
{
	return pkt->original_pkt;
}

/**
 * Fragments other than the one with no offset do not contain a layer-4 header.
 * If this returns false, you should not try to extract a layer-4 header from "skb".
 */
static inline bool pkt_has_l4_hdr(const struct packet *pkt)
{
	return skb_transport_header(pkt->skb) != pkt_payload(pkt);
}

/**
 * Returns the length of "skb"'s layer-3 header, including options or extension headers.
 * Only counts bytes actually present within skb. In other words, if skb is fragmented, the
 * headers of the other fragments are ignored.
 * Also, it doesn't count inner l3 headers (from ICMP errors).
 */
static inline unsigned int pkt_l3hdr_len(const struct packet *pkt)
{
	return skb_transport_header(pkt->skb) - skb_network_header(pkt->skb);
}

/**
 * Returns the length of "skb"'s layer-4 header, including options.
 * Returns zero if skb has no transport header.
 * Only counts bytes actually present within skb. In other words, if skb is fragmented, any
 * headers in any other fragments are ignored.
 * Also, it doesn't count inner l4 headers (from ICMP errors).
 */
static inline unsigned int pkt_l4hdr_len(const struct packet *pkt)
{
	return pkt_payload(pkt) - (void *) skb_transport_header(pkt->skb);
}

/**
 * Returns the length of skb's layer-3 and layer-4 headers.
 * Only counts bytes actually present within skb. In other words, if skb is fragmented, the
 * headers of the other fragments are ignored.
 * Also, it doesn't count inner headers (from ICMP errors).
 */
static inline unsigned int pkt_hdrs_len(const struct packet *pkt)
{
	return pkt_payload(pkt) - (void *) skb_network_header(pkt->skb);
}

/**
 * Returns the length of "skb"'s layer-4 payload.
 * Only counts bytes actually present within skb. In other words, if skb is fragmented, the
 * layer-4 payload of the other fragments is ignored.
 */
static inline unsigned int pkt_payload_len_frag(const struct packet *pkt)
{
	/* See skb_len() for relevant comments. */

	if (!pkt_is_fragment(pkt))
		return pkt->skb->len - pkt_hdrs_len(pkt);

	return skb_pagelen(pkt->skb) - (skb_shinfo(pkt->skb)->frag_list ? pkt_hdrs_len(pkt) : 0);
}

/**
 * Returns the length of "skb"'s layer-4 payload.
 * Includes the entire layer-4 payload (ie. ignores fragmentation).
 *
 * This function is only compatible with "full packets"; the result is otherwise undefined.
 * A "full packet" is either a non-fragmented packet, or a fragment whose frag_list contains all
 * the remaining fragments.
 */
static inline unsigned int pkt_payload_len_pkt(const struct packet *pkt)
{
	return pkt->skb->len - pkt_hdrs_len(pkt);
}

/**
 * Returns the length of "skb"'s layer-3 payload.
 * Only counts bytes actually present within skb. In other words, if skb is fragmented, the
 * layer-3 payload of the other fragments is ignored.
 */
static inline unsigned int pkt_l3payload_len(const struct packet *pkt)
{
	return pkt_l4hdr_len(pkt) + pkt_payload_len_frag(pkt);
}

/**
 * Returns the length of "skb"'s layer-3 payload.
 * Includes the entire layer-3 payload (ie. ignores fragmentation).
 *
 * This function is only compatible with "full packets"; the result is otherwise undefined.
 * A "full packet" is either a non-fragmented packet, or a fragment whose frag_list contains all
 * the remaining fragments.
 */
static inline unsigned int pkt_datagram_len(const struct packet *pkt)
{
	return pkt->skb->len - pkt_l3hdr_len(pkt);
}

/**
 * Returns the length of skb as a layer-3 packet. It includes layer 3 headers and layer 3 payload.
 *
 * It's supposed to replace skb->len in certain situations. This is because skb->len also counts
 * bytes present in other fragments, and that is not always what a NAT64 wants.
 */
static inline unsigned int pkt_len(const struct packet *pkt)
{
	/*
	 * Note, we can't depend on a nat64_is_stateful() here because frag_list is the official Linux
	 * fragment representation, therefore the absence of defrag doesn't strictly mean Jool will
	 * never see empty frag_lists (also viceversa for robustness).
	 */

	if (!pkt_is_fragment(pkt)) {
		/*
		 * Because stateless operation doesn't enforce the presence of defrags,
		 * stateless Jool typically does this.
		 * skb->len is headroom + page data + frag_list.
		 * frag_list is empty, so it doesn't harm us.
		 */
		return pkt->skb->len;
	}

	/*
	 * This is what happens when defragmentation is in the way. Stateful Jool typically has to do
	 * this.
	 * In the first fragment, pagelen contains everything we need (l3 header to payload).
	 * In subsequent fragments, pagelen doesn't count the headers (since data points to payload)
	 * so we add it ourselves.
	 *
	 * Note that skb_pagelen() is a gargantuan inline function, so we don't want to call it twice
	 * or something.
	 */
	return skb_pagelen(pkt->skb) + (skb_shinfo(pkt->skb)->frag_list ? 0 : pkt_hdrs_len(pkt));
}

static inline bool pkt_is_icmp6_error(const struct packet *pkt)
{
	return pkt_l4_proto(pkt) == L4PROTO_ICMP && is_icmp6_error(pkt_icmp6_hdr(pkt)->icmp6_type);
}

static inline bool pkt_is_icmp4_error(const struct packet *pkt)
{
	return pkt_l4_proto(pkt) == L4PROTO_ICMP && is_icmp4_error(pkt_icmp4_hdr(pkt)->type);
}

/**
 * Ensures "skb" isn't corrupted and initializes "pkt" out of it.
 *
 * After this function, code can assume:
 * - skb contains full l3 and l4 headers (including inner ones), their order seems to make sense,
 *   and they are all within the head room of skb.
 * - skb's payload isn't truncated (though inner packet payload might).
 * - The pkt_* functions above can now be used on pkt.
 * - The length fields in the l3 headers can be relied upon.
 *
 * Healthy layer 4 checksums and lengths are not guaranteed, but that's not an issue since this
 * kind of corruption should be translated along (see validate_icmp6_csum()).
 *
 * Also, this function does not ensure "skb" is either TCP, UDP or ICMP. This is because stateless
 * Jool must translate other protocols in a best-effort basis.
 *
 * This function can change the packet's pointers. If you eg. stored a pointer to
 * skb_network_header(skb), you will need to assign it again (by calling skb_network_header again).
 */
int pkt_init_ipv6(struct packet *pkt, struct sk_buff *skb);
int pkt_init_ipv4(struct packet *pkt, struct sk_buff *skb);
/**
 * @}
 */

/**
 * Outputs "skb" in the log.
 */
void pkt_print(struct packet *pkt);

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
int validate_icmp6_csum(struct packet *pkt);
int validate_icmp4_csum(struct packet *pkt);
/**
 * @}
 */

#endif /* _JOOL_MOD_PACKET_H */
