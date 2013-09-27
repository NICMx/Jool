#ifndef _NF_NAT64_PACKET_H
#define _NF_NAT64_PACKET_H

#include <linux/skbuff.h>
#include <linux/netfilter.h>
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
 * Unlike most modules, this one has three function prefixes:
 * - "pktmod_" stands for functions affecting the whole module.
 * - "pkt_" refers to functions meant to interact with struct packet.
 * - "frag_" refers to functions meant to interact with struct fragment.
 * There are also functions lacking a prefix. These are for general interaction with oddly-designed
 * kernel packet-related structures.
 */


/*	-------------------
	-- Packet module --
	------------------- */

/** This module is configurable. Please call this at the beggining to load the default values. */
int pktmod_init(void);
/** Call this to free any memory held by this module. */
void pktmod_destroy(void);
/**
 * Synchronization-safely returns the current configuration's fragment timeout.
 * fragment timeout is the maximum time any fragment should remain in memory. If that much time has
 * passed, it's most likely because at least one of its siblings died during shipping, and as such
 * reassembly is impossible.
 */
unsigned int pktmod_get_fragment_timeout(void);


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
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	return frag_off >> 3;
}

/** Returns a hack-free version of the 'Fragment offset' field from the "hdr" IPv4 header. */
static inline __u16 get_fragment_offset_ipv4(struct iphdr *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	return frag_off & IP_OFFSET;
}

/**
 * frag_hdr.frag_off is actually a combination of the 'More fragments' flag and the
 * 'Fragment offset' field. This function is a one-liner for creating a settable frag_off.
 */
static inline __be16 build_ipv6_frag_off_field(__u16 frag_offset, bool mf)
{
	__u16 result = (frag_offset << 3)
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
			| (frag_offset << 0);
	return cpu_to_be16(result);
}


/* TODO Why doesn't this belong to types? */
enum verdict {
	/** No problems thus far, processing of the packet can continue. */
	VER_CONTINUE = -1,
	/** Packet is not meant for translation. Please hand it to the local host. */
	VER_ACCEPT = NF_ACCEPT,
	/** Packet is invalid and should be dropped. */
	VER_DROP = NF_DROP,
	/*
	 * Packet is a fragment, and I need more information to be able to translate it, so I'll keep
	 * it for a while.
	 */
	VER_STOLEN = NF_STOLEN,
};


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
		enum l3_proto proto;
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
		enum l4_proto proto;
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
 * Allocates "frag_out" and initializes it out of "skb".
 * Assumes that "skb" represents a IPv6 packet.
 */
enum verdict frag_create_ipv6(struct sk_buff *skb, struct fragment **frag_out);
/**
 * Allocates "frag_out" and initializes it out of "skb".
 * Assumes that "skb" represents a IPv4 packet.
 */
enum verdict frag_create_ipv4(struct sk_buff *skb, struct fragment **frag_out);
/** Allocates "out" under the assumption that a skb is going to be created from it. */
enum verdict frag_create_empty(struct fragment **out);
/** Collapses all of "frag"'s fields into "frag".skb (i. e. creates a skb out of "frag"). */
enum verdict frag_create_skb(struct fragment *frag);
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
	/* TODO recordatorio: No hemos seteado esto en el de salida. */
	struct fragment *first_fragment;

	/**
	 * Number of bytes that have to be collected for the packet to be complete.
	 *
	 * If this is zero, then we still don't know the total length (the only way to know this is
	 * to infer it from the last fragment).
	 *
	 * This is only relevant when the fragments are being collected. After the packet_db module,
	 * you should probably ignore it (See the packet_db module for information on why we're
	 * collecting related fragments even though we're not reassembling).
	 */
	u16 total_bytes;
	/**
	 * Number of bytes that have been collected so far.
	 *
	 * This is only relevant when the fragments are being collected. After the packet_db module,
	 * you should probably ignore it.
	 *
	 * This is only relevant when the fragments are being collected. After the packet_db module,
	 * you should probably ignore it (See the packet_db module for information on why we're
	 * collecting related fragments even though we're not reassembling).
	 */
	u16 current_bytes;
	/**
	 * Identification of this "fragment stream". Identification field from the IPv4 header or IPv6
	 * fragment header.
	 */
	u32 fragment_id;
	/* Millisecond from the epoch at which Jool should forget about this "fragment stream". */
	unsigned int dying_time;

	/** Node used to link this packet in packet_db's "list" list. */
	struct list_head pkt_list_node;
};

/**
 * Allocates and initializes a packet out of "frag"'s contents. Includes "frag" in its list.
 * Assumes that "frag" represents IPv6 data.
 */
struct packet *pkt_create_ipv6(struct fragment *frag);
/**
 * Allocates and initializes a packet out of "frag"'s contents. Includes "frag" in its list.
 * Assumes that "frag" represents IPv4 data.
 */
struct packet *pkt_create_ipv4(struct fragment *frag);
/**
 * Adds "frag" to "pkt"'s fragment list, and updates "pkt"'s counters and metadata.
 * Assumes that both "pkt" and "frag" represent IPv6 data.
 */
void pkt_add_frag_ipv6(struct packet *pkt, struct fragment *frag);
/**
 * Adds "frag" to "pkt"'s fragment list, and updates "pkt"'s counters and metadata.
 * Assumes that both "pkt" and "frag" represent IPv4 data.
 */
void pkt_add_frag_ipv4(struct packet *pkt, struct fragment *frag);
/** Returns true if all of "pkt"'s fragments have arrived. */
bool pkt_is_complete(struct packet *pkt);
/** Frees "pkt"'s contents. If "free_pkt" is true, frees "pkt" as well. */
void pkt_kfree(struct packet *pkt, bool free_pkt);

/** Getter for "pkt"'s network protocol. */
static inline enum l3_proto pkt_get_l3proto(struct packet *pkt)
{
	return pkt->first_fragment->l3_hdr.proto;
}

/** Getter for "pkt"'s transport protocol. */
static inline enum l4_proto pkt_get_l4proto(struct packet *pkt)
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


#endif /* _NF_NAT64_PACKET_H */
