#ifndef _NF_NAT64_TRANSLATING_THE_PACKET_H
#define _NF_NAT64_TRANSLATING_THE_PACKET_H

/**
 * @file
 * Fourth and last step of the Nat64 translation algorithm: "Translating the Packet", as defined in
 * RFC6146 section 3.7.
 *
 * Abbreviations seen in this submodule:
 * - hdr = header
 * - src = source
 * - dst = destination
 * - frag = fragment
 * - len = length
 * - ptr = pointer
 * - in = incoming (Note, not "inner")
 * - out = outgoing
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_tuple.h>


/**
 * A summary of an incoming packet. Contains some info that's not immediately obvious from the
 * sk_buff and then some. The point is to avoid having to recompute stuff whenever it's needed.
 * Most code should assume it is already and completely populated.
 */
struct packet_in
{
	/**
	 * A pointer to the incoming packet, in case you need something that's not in the packet_in.
	 * This field will NOT be set if this packet_in belongs to a packet inside of a packet (Because
	 * there was never a sk_buff to begin with).
	 */
	struct sk_buff *packet;
	/**
	 * "packet"'s address, except already translated by "Computing the Outgoing Tuple".
	 * We're supposed to write it in the outgoing packet.
	 */
	struct nf_conntrack_tuple *tuple;

	/**
	 * "packet"'s IP header. Think skb_network_header(packet_in.packet), except usable when
	 * "packet_in.packet" is unset.
	 */
	void *l3_hdr;
	/**
	 * "l3_hdr"'s type. Either IPPROTO_IP or IPPROTO_IPV6.
	 * You don't need to query this all the time. If we're translating from 4 to 6 this will always
	 * be 4, else 6.
	 */
	int l3_hdr_type;
	/**
	 * "l3_hdr"'s total length. That includes options and extension headers. So it's also the
	 * distance from the network header to the transport header. Please remember that both ICMP
	 * protocols behave like transport protocols here.
	 */
	__u16 l3_hdr_len;
	/**
	 * "l3_hdr"'s length, stripped of options and extension headers.
	 * So it's just a sizeof(struct iphdr) or a sizeof(struct ipv6hdr).
	 */
	__u16 l3_hdr_basic_len;
	/**
	 * A helper function, that can help you get a packet's l3_hdr_len, assuming its l3_hdr_type is
	 * the same as this packet_in's.
	 */
	__u16 (*compute_l3_hdr_len)(void *l3_hdr);

	/**
	 * skb_transport_header(packet_in.packet)'s type.
	 * Either IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP, NEXTHDR_UDP, NEXTHDR_TCP or NEXTHDR_ICMP.
	 */
	int l4_hdr_type;
	/**
	 * skb_transport_header(packet_in.packet)'s length.
	 * Recall that TCP headers might contain options, which will also be included here.
	 */
	__u16 l4_hdr_len;

	/**
	 * The packet's payload, which is also the layer 4's payload.
	 * For some annoying reason this one is absent from sk_buff.
	 */
	void *payload;
	/**
	 * "payload"'s length.
	 * Also distance from the layer 4 header's end to the absolute end of the packet.
	 */
	__u16 payload_len;
};

/**
 * A fetal version of the outgoing packet. Contains the pieces that will eventually merge into it.
 *
 * The length of the outgoing packet is generally unknown until the end, so a fully-fledged sk_buff
 * cannot be allocated from the beggining. So keep in mind that the l3_hdr, l4_hdr and payload
 * fields will not point to contiguous chunks of memory as one might be accustomed to expect.
 *
 * Most of "Translating the Packet" is about sequentially setting fields here. Code can generally
 * assume that lower layer fields than the ones being currently processed have already been set.
 * The only exceptions are the headers' checksums and lenghts, since they require the rest of the
 * packet to be known, so they have to be computed at the very end.
 */
struct packet_out
{
	/**
	 * "l3_hdr"'s type. Either IPPROTO_IP or IPPROTO_IPV6.
	 * You don't need to query this all the time. If we're translating from 4 to 6 this will always
	 * be 6, else 4.
	 */
	int l3_hdr_type;
	/**
	 * "l3_hdr"'s length. Works the same as packet_in.l3_hdr_len.
	 */
	__u16 l3_hdr_len;
	/**
	 * The IP header first allocated.
	 */
	void *l3_hdr;

	/**
	 * "l4_hdr"'s type.
	 * Either IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP, NEXTHDR_UDP, NEXTHDR_TCP or NEXTHDR_ICMP.
	 */
	int l4_hdr_type;
	/**
	 * "l4_hdr"'s length.
	 * Recall that TCP headers might contain options, which will also be included here.
	 */
	__u16 l4_hdr_len;
	/**
	 * The layer 4 header first allocated.
	 * Sometimes this points to the incoming packet's layer 4 header, because it doesn't need to
	 * change so it may be copied to packet_out.packet directly.
	 * Only the ICMP pipelines require to allocate this, actually.
	 */
	void *l4_hdr;

	/**
	 * "payload"'s length. Works the same as packet_in.payload_len.
	 */
	__u16 payload_len;
	/**
	 * The payload first allocated.
	 * Sometimes this points to the incoming packet's payload, because it doesn't need to change so
	 * it may be copied to packet_out.packet directly. See "payload_needs_kfreeing".
	 */
	unsigned char *payload;
	/**
	 * If "payload" was allocated instead of pointing to the original payload, this will be "true".
	 */
	bool payload_needs_kfreeing;

	/**
	 * All of the above, assembled into a kernel-compatible packet.
	 * This is what "Translate the Packet" will return to the outside.
	 */
	struct sk_buff *packet;
};
#define INIT_PACKET_OUT { 0, 0, NULL, 0, 0, NULL, 0, NULL, false, NULL }

/**
 * The sequence of functions "Translating the Packet" will execute to do its job.
 * Which functions are set depend on whether we're going from 4 to 6 or 6 to 4 and whether the
 * datagram is a TCP, UDP or ICMP one.
 */
struct pipeline
{
	/**
	 * The function that will translate the layer-3 header.
	 * Its purpose if to set the variables from "out" which are prefixed by "l3_", based on the
	 * packet described by "in".
	 *
	 * @param in packet being translated.
	 * @param out packet being created. When this function hits the scene, this structure is
	 *			completely empty.
	 * @return "true" on success, "false" on failure.
	 */
	bool (*l3_hdr_function)(struct packet_in *in, struct packet_out *out);
	/**
	 * The function that will translate the layer-4 header and the payload. Layer 4 and payload are
	 * combined in a single function due to their strong interdependence.
	 * Its purpose is to set the variables from "out" which are prefixed by "l4_" or "payload",
	 * based on the packet described by "in".
	 *
	 * @param in packet being translated.
	 * @param out packet being created. When this function hits the scene, "out"'s "l3_*" fields
	 *			have already been set, in case you can benefit from using them.
	 * @return "true" on success, "false" on failure.
	 */
	bool (*l4_hdr_and_payload_function)(struct packet_in *in, struct packet_out *out);
	/**
	 * The function that will merge "out.l3_hdr", "out.l4_hdr" and "out.payload" into a sk_buff.
	 * Its purpose is to set the "out.packet" variable.
	 *
	 * @param in packet being translated.
	 * @param out packet being created. When this function hits the scene, the only field from "out"
	 *			that hasn't been set is "out.packet".
	 * @return "true" on success, "false" on failure.
	 */
	bool (*create_skb_function)(struct packet_out *out);
	/**
	 * Post-processing involving the layer 3 header.
	 *
	 * Currently, this function fixes the header's lengths and checksum, which cannot be done in the
	 * functions above given that they generally require the packet to be assembled and ready.
	 * Not all lengths and checksums have that requirement, but just to be consistent do it always
	 * here, please.
	 *
	 * @param out outgoing packet to do the post-processing on. Note, out.l3_hdr, out.l4_hdr and
	 *			out.payload point to garbage given that the packet has already been assembled.
	 *			When you want to access the headers, use out.packet.
	 * @return "true" on success, "false" on failure.
	 */
	bool (*l3_post_function)(struct packet_out *out);
	/**
	 * Post-processing involving the layer 4 header. See pipeline.l3_post_function.
	 *
	 * @param out same as pipeline.l3_post_function.out.
	 * @return "true" on success, "false" on failure.
	 */
	bool (*l4_post_function)(struct packet_out *out);
};


/**
 * The core function of this submodule.
 * If "skb_in" is a IPv4 packet, creates a IPv6 equivalent and stores it in "*skb_out".
 * If "skb_in" is a IPv6 packet, creates a IPv4 equivalent and stores it in "*skb_out".
 *
 * @param tuple translated addresses from "skb_in".
 * @param skb_in the incoming packet.
 * @param skb_out out parameter, where the outgoing packet will be placed.
 */
bool nat64_translating_the_packet(struct nf_conntrack_tuple *tuple, struct sk_buff *skb_in,
		struct sk_buff **skb_out);

/**
 * Interprets in.payload as an independent packet, translates its layer 3 header (using
 * "l3_hdr_function") and places the result in out.payload.
 *
 * I've more or less arbitrarily decided that errors within this function will not trigger a packet
 * drop. If the translation of the inner packet fails, the original inner packet will be returned.
 * If this decision proves troublesome, just adjust the code to return false on failure.
 */
bool translate_inner_packet(struct packet_in *in, struct packet_out *out,
		bool (*l3_hdr_function)(struct packet_in *, struct packet_out *));


#endif /* _NF_NAT64_TRANSLATING_THE_PACKET_H */
