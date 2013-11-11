#ifndef _NF_NAT64_PACKET_H
#define _NF_NAT64_PACKET_H

#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/ipv6_hdr_iterator.h"


/**
 * @file
 * Code meant to ease the handling of packets.
 *
 * We found struct sk_buff to be a little NAT64 unfriendly, so we ended up encapsulating it.
 *
 * struct fragment encapsulates a sk_buff. It contains the sk_buff and a bunch of metadata about it.
 * struct packet represents a group of related fragments (Jool is almost never supposed to
 * reassemble).
 *
 * So, at a high level, Jool handles packets rather than sk_buffs. We've had difficulties finding
 * natural fragments out there though, so most of the time it's just one struct packet containing
 * one struct fragment containing one struct sk_buff.
 *
 * Unlike most modules, this one has two function prefixes:
 * - "pkt_" refers to functions meant to interact with struct packet.
 * - "frag_" refers to functions meant to interact with struct fragment.
 * There are also functions lacking a prefix. These are for general interaction with oddly-designed
 * kernel packet-related structures.
 */


/*	---------------
	--- General ---
	--------------- */

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
 */
static inline __be16 build_ipv4_frag_off_field(bool df, bool mf, __u16 frag_offset)
{
	__u16 result = (df << 14)
			| (mf << 13)
			| (frag_offset >> 3); /* 3 bit shifts to the right == division by 8. */
	return cpu_to_be16(result);
}

verdict validate_csum_icmp6(struct sk_buff *skb, int datagram_len);
verdict validate_csum_icmp4(struct sk_buff *skb, int datagram_len);


/*	---------------
	-- Fragments --
	--------------- */

/**
 * An IPv4 or IPv6 fragment, which might or might not be the only one.
 */
struct fragment {
	/** Buffer from the socket we're storing data for. */
	struct sk_buff *skb;
	/** Destination of the packet. */
	struct dst_entry *dst;

	/** Network header. */
	struct {
		/** Indicator of how the "ptr" variable should be read. */
		l3_protocol proto;
		/** Length of the header, including options (IPv4) or extension headers (IPv6). */
		int len;
		/**
		 * The packet's actual network header.
		 * Be warned that this sometimes points to something inside of "skb", sometimes it doesn't.
		 */
		void *ptr;
		/**
		 * Whether the destructor should call kfree() on "ptr".
		 * Eg. when "ptr" points to something inside of "skb", the latter should be released, the
		 * former should not.
		 */
		bool ptr_needs_kfree;
	} l3_hdr;

	/** Transport header. */
	struct {
		/** Indicator of how the "ptr" variable should be read. */
		l4_protocol proto;
		/** Length of the header, including TCP options and any other crap before the payload. */
		int len;
		/**
		 * The packet's actual transport header.
		 * Be warned that this sometimes points to something inside of "skb", sometimes it doesn't.
		 */
		void *ptr;
		/** Whether the destructor should call kfree() on "ptr". */
		bool ptr_needs_kfree;
	} l4_hdr;

	/** Transport payload. */
	struct {
		/** Length of the data pointed by "ptr". */
		int len;
		/**
		 * The packet's actual payload.
		 * Be warned that this sometimes points to something inside of "skb", sometimes it doesn't.
		 */
		void *ptr;
		/** Whether the destructor should call kfree() on "ptr". */
		bool ptr_needs_kfree;
	} payload;

	/** Node used to link this fragment in the packet.fragments list. */
	struct list_head next;
};

/**
 * Allocates a fragment, initializes it out of "skb" and returns it.
 * Assumes that "skb" represents a IPv6 packet.
 */
struct fragment *frag_create_ipv6(struct sk_buff *skb);
/**
 * Allocates a fragment, initializes it out of "skb" and returns it.
 * Assumes that "skb" represents a IPv4 packet.
 */
struct fragment *frag_create_ipv4(struct sk_buff *skb);
/** Allocates "out" under the assumption that a skb is going to be created from it. */
verdict frag_create_empty(struct fragment **out);
/** Collapses all of "frag"'s fields into "frag".skb (i. e. creates a skb out of "frag"). */
verdict frag_create_skb(struct fragment *frag);
bool frag_is_fragmented(struct fragment *frag);
/** Best-effortlessly prints "frag" on the log. Intended for debugging. */
void frag_print(struct fragment *frag);
/** Releases "frag" and its contents from memory. */
void frag_kfree(struct fragment *frag);

/** Accesor of "frag".l3_hdr.ptr, intended to strongly imply that it points to a IPv6 header. */
static inline struct ipv6hdr *frag_get_ipv6_hdr(struct fragment *frag)
{
	return frag->l3_hdr.ptr;
}

/** One-liner for getting "frag"'s fragment header, wherever it is. */
static inline struct frag_hdr *frag_get_fragment_hdr(struct fragment *frag)
{
	return get_extension_header(frag_get_ipv6_hdr(frag), NEXTHDR_FRAGMENT);
}

/** Accesor of "frag".l3_hdr.ptr, intended to strongly imply that it points to a IPv4 header. */
static inline struct iphdr *frag_get_ipv4_hdr(struct fragment *frag)
{
	return frag->l3_hdr.ptr;
}

/** Accesor of "frag".l4_hdr.ptr, intended to strongly imply that it points to a TCP header. */
static inline struct tcphdr *frag_get_tcp_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

/** Accesor of "frag".l4_hdr.ptr, intended to strongly imply that it points to a UDP header. */
static inline struct udphdr *frag_get_udp_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

/** Accesor of "frag".l4_hdr.ptr, intended to strongly imply that it points to a ICMPv6 header. */
static inline struct icmp6hdr *frag_get_icmp6_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

/** Accesor of "frag".l4_hdr.ptr, intended to strongly imply that it points to a ICMPv4 header. */
static inline struct icmphdr *frag_get_icmp4_hdr(struct fragment *frag)
{
	return frag->l4_hdr.ptr;
}

/** Accesor of "frag".payload.ptr. */
static inline unsigned char *frag_get_payload(struct fragment *frag)
{
	return frag->payload.ptr;
}


/*	---------------
	--- Packets ---
	--------------- */

/**
 * A group of fragments, which would normally be assembled into a proper layer-3 packet.
 * If there is no fragmentation, then THERE IS STILL ONE FRAGMENT.
 */
struct packet {
	/** The fragments this packet is composed of. */
	struct list_head fragments;
	/** Quick accesor of the one fragment that contains the layer-4 headers. */
	struct fragment *first_fragment;
};

/** Allocates and initializes a packet out of "frag"'s contents. Includes "frag" in its list. */
struct packet *pkt_create(struct fragment *frag);
/** Adds "frag" to "pkt". Has the added comfort of updating "pkt".first_fragment if applies. */
void pkt_add_frag(struct packet *pkt, struct fragment *frag);
/** Frees "pkt"'s contents. If "free_pkt" is true, frees "pkt" as well. */
void pkt_kfree(struct packet *pkt, bool free_pkt);

/** Getter for "pkt"'s network protocol. */
static inline l3_protocol pkt_get_l3proto(struct packet *pkt)
{
	return pkt->first_fragment->l3_hdr.proto;
}

/** Getter for "pkt"'s transport protocol. */
static inline l4_protocol pkt_get_l4proto(struct packet *pkt)
{
	return pkt->first_fragment->l4_hdr.proto;
}

/** Getter for "pkt"'s IPv4 source address. */
static inline void pkt_get_ipv4_src_addr(struct packet *pkt, struct in_addr *result)
{
	struct iphdr *hdr4 = frag_get_ipv4_hdr(pkt->first_fragment);
	result->s_addr = hdr4->saddr;
}

/** Getter for "pkt"'s IPv4 destination address. */
static inline void pkt_get_ipv4_dst_addr(struct packet *pkt, struct in_addr *result)
{
	struct iphdr *hdr4 = frag_get_ipv4_hdr(pkt->first_fragment);
	result->s_addr = hdr4->daddr;
}

/** Getter for "pkt"'s IPv6 source address. */
static inline struct in6_addr *pkt_get_ipv6_src_addr(struct packet *pkt)
{
	struct ipv6hdr *hdr6 = frag_get_ipv6_hdr(pkt->first_fragment);
	return &hdr6->saddr;
}

/** Getter for "pkt"'s IPv6 destination address. */
static inline struct in6_addr *pkt_get_ipv6_dst_addr(struct packet *pkt)
{
	struct ipv6hdr *hdr6 = frag_get_ipv6_hdr(pkt->first_fragment);
	return &hdr6->daddr;
}

/* TODO try to always use this. */
static inline struct fragment *pkt_get_first_frag(struct packet *pkt)
{
	return list_entry(pkt->fragments.next, struct fragment, next);
}


#endif /* _NF_NAT64_PACKET_H */
