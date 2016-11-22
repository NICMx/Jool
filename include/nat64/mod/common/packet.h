#ifndef _JOOL_MOD_PACKET_H
#define _JOOL_MOD_PACKET_H

/**
 * @file
 * Random packet-related functions.
 *
 * You might want to be aware of the different types of packets the kernel can
 * throw at Jool; see below.
 *
 * (Note that when I say "fragment" I mean "IP fragment". "Page fragments" are
 * something else altogether and are somewhat transparent to Jool. All the
 * variations below can be paged, except for subsequent packets already
 * represented as pages.)
 *
 * 1. A "real full packet" is a packet that is not fragmented. It is a single
 *    skb with fragment offset = 0 and MF = 0.
 * 2. A "fake full packet" is a packet which is fragmented but the kernel API
 *    wants us to believe otherwise.
 *    These are "assembled" skbs in that the skb points to the first fragment
 *    and the remaining fragments are queued in skb_shinfo(skb)->frag_list.
 *    Though many kernel functions want us to believe the skb is a real full
 *    packet, and ideally we would follow suit, doing surgery on individual
 *    fragments is sometimes necessary evil for PMTU reasons.
 *
 * (A "full packet" is either a real full packet or a fake full packet.)
 *
 * 3. A "fragmented packet" is a normal fragmented packet that hasn't suffered
 *    defrag alterations.
 *    In other words, fragment offset > 0 and/or MF == true, shinfo->frag_list
 *    isn't populated and the skb is not queued in any other packet's frag_list.
 *    These are fragments but are separated from their ilk during translation as
 *    you would expect from a stateless forwarding machine.
 * 4. An "internal packet" is a packet wrapped as payload in an ICMP error.
 *    These are set up and used by the RFC6145 submodule.
 *    Internal packets can be truncated! Header lengths might contradict the
 *    sizes from the skb fields. Jool in general should *rarely* rely on header
 *    lengths.
 *    I repeat: Because of internal packets, JOOL IN GENERAL SHOULD RARELY RELY
 *    ON HEADER LENGTHS!
 * 5. A "subsequent packet" is a fragment that has been queued in some fake full
 *    packet's frag_list. These packets are special in that they have stripped
 *    (deleted) l3 headers for no apparent reason.
 *    As I understand it, while forwarding, the kernel regenerates "subsequent
 *    headers" from scratch so any special differences between the original
 *    headers are lost. Ever since the atomic fragment hack was removed from the
 *    xlat standards this is no longer harmful so we don't mind it anymore.
 *    So yeah, do not translate subsequent headers. They do not exist.
 *    Another thing worth mentioning is that some kernels are even more insane
 *    in that they queue subsequent fragments in ->frags instead of ->frag_list.
 *    This is, in fact, also not entirely harmful because we can simply transfer
 *    pages as they are and the kernel should automatically turn them into
 *    fragments if they won't fit through the MTU. I don't think this is as
 *    deterministic as it should be, since the kernel might not be aware of the
 *    path MTU (and therefore linearize fragment pages), but there is nothing
 *    else we can do because there is nothing that will tell us whether a
 *    ->frags member is a fragment or a page.
 *
 * TODO copy pages "as they are". We're currently linearizing them...
 *
 * For the most part, full/fragmented/internal packets can be handled similarly.
 * Subsequent packets, freaks of nature as they are, are thankfully often
 * transparent to us.
 *
 * @see https://github.com/NICMx/Jool/wiki/nf_defrag_ipv4-and-nf_defrag_ipv6
 */

#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include "nat64/mod/common/types.h"


/** Returns a hack-free version of the 'Traffic class' field from @hdr. */
static inline __u8 get_traffic_class(const struct ipv6hdr *hdr)
{
	__u8 upper_bits = hdr->priority;
	__u8 lower_bits = hdr->flow_lbl[0] >> 4;
	return (upper_bits << 4) | lower_bits;
}

/**
 * Returns a big endian (but otherwise hack-free) version of the 'Flow label'
 * field from @hdr.
 */
static inline __be32 get_flow_label(const struct ipv6hdr *hdr)
{
	return (*(__be32 *) hdr) & IPV6_FLOWLABEL_MASK;
}

/** Returns IP_DF if the DF flag from @hdr is set, 0 otherwise. */
static inline __u16 is_df_set(const struct iphdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP_DF;
}

/** Returns IP6_MF if the MF flag from @hdr is set, 0 otherwise. */
static inline __u16 is_mf_set_ipv6(const struct frag_hdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP6_MF;
}

/** Returns IP_MF if the MF flag from @hdr is set, 0 otherwise. */
static inline __u16 is_mf_set_ipv4(const struct iphdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP_MF;
}

/** Returns a hack-free version of the 'Fragment offset' field from @hdr. */
static inline __u16 get_fragment_offset_ipv6(const struct frag_hdr *hdr)
{
	return be16_to_cpu(hdr->frag_off) & 0xFFF8U;
}

/** Returns a hack-free version of the 'Fragment offset' field from @hdr. */
static inline __u16 get_fragment_offset_ipv4(const struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	/* 3 bit shifts to the left == multiplication by 8. */
	return (frag_off & IP_OFFSET) << 3;
}

/**
 * Pretends @skb's IPv6 header has a "total length" field and returns its value.
 * This function exists because turning "payload length" into "total length" by
 * hand takes almost a full line by itself, which forces us to break lines.
 */
static inline unsigned int get_tot_len_ipv6(const struct sk_buff *skb)
{
	return sizeof(struct ipv6hdr) + be16_to_cpu(ipv6_hdr(skb)->payload_len);
}

/**
 * @{
 * Does @hdr belong to a "first fragment"?
 * A non-fragmented packet is also considered a first fragment.
 */
static inline bool is_first_frag4(const struct iphdr *hdr)
{
	return get_fragment_offset_ipv4(hdr) == 0;
}

static inline bool is_first_frag6(const struct frag_hdr *hdr)
{
	return hdr ? (get_fragment_offset_ipv6(hdr) == 0) : true;
}
/**
 * @}
 */

/**
 * @{
 * Is @hdr's packet a fragment?
 */
static inline bool is_fragmented_ipv4(const struct iphdr *hdr)
{
	return (get_fragment_offset_ipv4(hdr) != 0) || is_mf_set_ipv4(hdr);
}

static inline bool is_fragmented_ipv6(const struct frag_hdr *hdr)
{
	if (!hdr)
		return false;
	return (get_fragment_offset_ipv6(hdr) != 0) || is_mf_set_ipv6(hdr);
}
/**
 * @}
 */

/**
 * frag_hdr.frag_off is actually a combination of the 'More fragments' flag and
 * the 'Fragment offset' field. This function is a one-liner for creating a
 * settable frag_off.
 * Note that fragment offset is measured in units of eight-byte blocks. That
 * means that you want @frag_offset to be a multiple of 8 if you want your
 * fragmentation to work properly.
 */
static inline __be16 build_ipv6_frag_off_field(__u16 frag_offset, __u16 mf)
{
	__u16 result = (frag_offset & 0xFFF8U) | (mf ? 1U : 0U);
	return cpu_to_be16(result);
}

/**
 * iphdr.frag_off is actually a combination of the DF flag, the MF flag and the
 * 'Fragment offset' field. This function is a one-liner for creating a settable
 * frag_off.
 * Note that fragment offset is measured in units of eight-byte blocks. That
 * means that you want @frag_offset to be a multiple of 8 if you want your
 * fragmentation to work properly.
 */
static inline __be16 build_ipv4_frag_off_field(const bool df, const __u16 mf,
		const __u16 frag_offset)
{
	__u16 result = (df ? (1U << 14) : 0)
			| (mf ? (1U << 13) : 0)
			/* 3 bit shifts to the right == division by 8. */
			| (frag_offset >> 3);
	return cpu_to_be16(result);
}

/**
 * Returns the size in bytes of @hdr, including options.
 * skbless variant of tcp_hdrlen().
 */
static inline unsigned int tcp_hdr_len(const struct tcphdr *hdr)
{
	return hdr->doff << 2;
}

/**
 * We need to store packet metadata, so we encapsulate sk_buffs into this.
 *
 * Do **not** use control buffers (skb->cb) for this purpose. The kernel is
 * known to misbehave and store information there which we should not override.
 *
 * By the way: Jool never creates `struct packet`s out of subsequent packets
 * alone. If you're holding a `struct packet`, you can be sure the contained skb
 * is one of the other variations.
 */
struct packet {
	struct sk_buff *skb;
	struct tuple tuple;

	/**
	 * Protocol of the layer-3 header of the packet.
	 * Yes, skb->proto has the same superpowers, but it's a little
	 * unreliable (it's not set in the Local Out chain).
	 * Also this spares me a switch in pkt_l3_proto() :p.
	 */
	enum l3_protocol l3_proto;
	/**
	 * Protocol of the layer-4 header of the packet. To the best of my
	 * knowledge, the kernel also uses skb->proto for this, but only on
	 * layer-4 code (of which Jool isn't).
	 * Skbs otherwise do not store a layer-4 identifier.
	 */
	enum l4_protocol l4_proto;
	/**
	 * Is this a subpacket, contained in an ICMP error?
	 * (Used by the RFC6145 code.)
	 */
	bool is_inner;
	/**
	 * Is the packet going to hairpin?
	 * Intrinsic EAM hairpinning only. RFC6052 hairpin and Simple EAM
	 * hairpin don't need any flags.
	 */
	bool is_hairpin;

	/**
	 * Quick pointer to skb's fragment header, if any.
	 */
	struct frag_hdr *hdr_frag;
	/**
	 * Pointer to the packet's payload.
	 * Because skbs only store pointers to headers.
	 *
	 * Sometimes the kernel seems to use skb->data for this. It would be
	 * troublesome if we did the same, however, since functions such as
	 * icmp_send() fail early when skb->data is after the layer-3 header.
	 *
	 * Note, even after the packet is validated, the payload can be paged
	 * (unlike headers). Do not access the data pointed by this field
	 * carelessly.
	 */
	void *payload;
	/**
	 * If this is an incoming packet (as in, incoming to Jool), this points
	 * to the same packet (pkt->original_pkt = pkt). Otherwise (which
	 * includes hairpin packets), this points to the original (incoming)
	 * packet.
	 * Used by the ICMP wrapper because it needs to reply the original
	 * packet, not the one being translated. Also relevant to pkt_queue.
	 */
	struct packet *original_pkt;

#ifdef BENCHMARK
	/**
	 * Log the time in epoch when this skb arrives to jool.
	 * For benchmark purposes.
	 */
	struct timespec start_time;
#endif
};

/**
 * Initializes @pkt using the rest of the arguments.
 */
static inline void pkt_fill(struct packet *pkt, struct sk_buff *skb,
		l3_protocol l3_proto, l4_protocol l4_proto,
		struct frag_hdr *hdr_frag, void *payload,
		struct packet *original_pkt)
{
	pkt->skb = skb;
	pkt->l3_proto = l3_proto;
	pkt->l4_proto = l4_proto;
	pkt->is_inner = 0;
	pkt->is_hairpin = false;
	pkt->hdr_frag = hdr_frag;
	pkt->payload = payload;
	pkt->original_pkt = original_pkt;
#ifdef BENCHMARK
	pkt->start_time = original_pkt->start_time;
#endif
}

/**
 * Returns @skb's layer-3 protocol in enum format.
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
 * Returns @skb's layer-4 protocol in enum format.
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

static inline bool pkt_is_intrinsic_hairpin(const struct packet *pkt)
{
	return pkt->is_hairpin;
}

static inline int pkt_payload_offset(const struct packet *pkt)
{
	/*
	 * It seems like the network header functions are cancelling each other.
	 * This is *NOT* the case!
	 * The point is to make the offset's reference the same as the network
	 * header's (whatever it is).
	 */
	return skb_network_offset(pkt->skb) + (pkt_payload(pkt)
			- (void *)skb_network_header(pkt->skb));
}

static inline struct packet *pkt_original_pkt(const struct packet *pkt)
{
	return pkt->original_pkt;
}

/**
 * Returns the length of @pkt as a layer-3 packet. It includes layer 3 headers
 * and layer 3 payload.
 *
 * It is supposed to replace @pkt->skb->len in certain situations. This is
 * because @pkt->skb->len also counts bytes present in subsequent fragments, and
 * that is not always what a translator wants.
 */
static inline unsigned int pkt_len(const struct packet *pkt)
{
	return skb_pagelen(pkt->skb);
}

/**
 * Returns the length of @pkt's layer-3 headers, including options or extension
 * headers.
 * Only counts bytes actually present within @pkt. In other words, headers of
 * any subsequent fragments linked to @pkt are ignored.
 * Also, it doesn't count inner l3 headers (from ICMP errors).
 */
static inline unsigned int pkt_l3hdr_len(const struct packet *pkt)
{
	return skb_transport_header(pkt->skb) - skb_network_header(pkt->skb);
}

/**
 * Returns the length of @pkt's layer-4 header, including options.
 * Returns zero if @pkt has no transport headers.
 * It doesn't count inner l4 headers (from ICMP errors).
 */
static inline unsigned int pkt_l4hdr_len(const struct packet *pkt)
{
	return pkt_payload(pkt) - (void *) skb_transport_header(pkt->skb);
}

/**
 * Returns the length of @pkt's layer-3 and layer-4 headers.
 * Only counts bytes actually present within @pkt. In other words, headers of
 * any subsequent fragments linked to @pkt are ignored.
 * Also, it doesn't count inner headers (from ICMP errors).
 */
static inline unsigned int pkt_hdrs_len(const struct packet *pkt)
{
	return pkt_payload(pkt) - (void *) skb_network_header(pkt->skb);
}

/**
 * Returns the length of @pkt's layer-4 payload.
 * Only counts bytes actually present within @pkt. In other words, payload of
 * any subsequent fragments linked to @pkt is ignored.
 */
static inline unsigned int pkt_payload_len_frag(const struct packet *pkt)
{
	return pkt_len(pkt) - pkt_hdrs_len(pkt);
}

/**
 * Returns the length of @pkt's layer-4 payload.
 * Includes the entire layer-4 payload (ie. including subsequent fragment
 * payload).
 *
 * This function is compatible with full and internal packets. Technically, it
 * might also be used with fragmented packets depending on context, but
 * pkt_payload_len_frag() would likely make more sense.
 */
static inline unsigned int pkt_payload_len_pkt(const struct packet *pkt)
{
	return pkt->skb->len - pkt_hdrs_len(pkt);
}

/**
 * Returns the length of @pkt's layer-3 payload.
 * Only counts bytes actually present within @pkt. In other words, payload of
 * any subsequent fragments linked to @pkt is ignored.
 */
static inline unsigned int pkt_l3payload_len(const struct packet *pkt)
{
	return pkt_len(pkt) - pkt_l3hdr_len(pkt);
}

/**
 * Returns the length of "skb"'s layer-3 payload.
 * Includes the entire layer-3 payload (ie. including subsequent fragment
 * payload).
 *
 * This function is only compatible with full packets; the result is otherwise
 * undefined.
 */
static inline unsigned int pkt_datagram_len(const struct packet *pkt)
{
	return pkt->skb->len - pkt_l3hdr_len(pkt);
}

static inline bool pkt_is_icmp6_error(const struct packet *pkt)
{
	return pkt_l4_proto(pkt) == L4PROTO_ICMP
			&& is_icmp6_error(pkt_icmp6_hdr(pkt)->icmp6_type);
}

static inline bool pkt_is_icmp4_error(const struct packet *pkt)
{
	return pkt_l4_proto(pkt) == L4PROTO_ICMP
			&& is_icmp4_error(pkt_icmp4_hdr(pkt)->type);
}

/**
 * Ensures @skb isn't corrupted and initializes @pkt out of it.
 *
 * After this function, code can assume:
 * - @skb contains full l3 and l4 headers (including inner ones), their order
 *   seems to make sense, and they are all within the head room of skb.
 * - @skb's payload isn't truncated (though inner packet payload might).
 * - The pkt_* functions above can now be used on @pkt.
 * - The length fields in the l3 headers can be relied upon.
 *
 * Healthy layer 4 checksums and lengths are not guaranteed, but that's not an
 * issue since this kind of corruption should be translated along (see
 * validate_icmp6_csum()).
 *
 * Also, this function does not ensure @skb is either TCP, UDP or ICMP. This is
 * because SIIT Jool must translate other protocols in a best-effort basis.
 *
 * This function can change the packet's pointers. If you eg. stored a pointer
 * to skb_network_header(skb), you will need to assign it again (by calling
 * skb_network_header() again).
 */
int pkt_init_ipv6(struct packet *pkt, struct sk_buff *skb);
int pkt_init_ipv4(struct packet *pkt, struct sk_buff *skb);
/**
 * @}
 */

/**
 * Outputs @pkt in the log.
 */
void pkt_print(struct packet *pkt);

#endif /* _JOOL_MOD_PACKET_H */
