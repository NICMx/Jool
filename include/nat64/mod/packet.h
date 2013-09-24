#ifndef _NF_NAT64_PACKET_H
#define _NF_NAT64_PACKET_H

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "nat64/comm/types.h"

/**
 * @file
 * Validations over network and transport headers. The rest of the module tends to assume these
 * have been performed already, so it's a mandatory second step (first being linearization).
 *
 * Some of the functions from the kernel (eg. ip_rcv()) already cover the network header
 * validations, so they might seem unnecesary. But the kernel does change sporadically, so I'd
 * rather keep them JIC.
 *
 * On the other hand, the transport header checks are a must, since the packet hasn't reached the
 * kernel's transport layer when the module kicks in.
 */

enum verdict {
	/** No problems thus far, processing of the packet can continue. */
	VER_CONTINUE = -1,
	/** Packet is not meant for translation. Please hand it to the local host. */
	VER_ACCEPT = NF_ACCEPT,
	/** Packet is invalid and should be dropped. */
	VER_DROP = NF_DROP,
	VER_STOLEN = NF_STOLEN,
};

/**
 * Validates the lengths and checksums of skb's IPv4 and transport headers.
 *
 * @param skb packet to validate.
 * @return validation result.
 */
enum verdict validate_skb_ipv4(struct sk_buff *skb);

/**
 * Validates the lengths and checksums of skb's IPv6 and transport headers.
 *
 * @param skb packet to validate.
 * @return validation result.
 */
enum verdict validate_skb_ipv6(struct sk_buff *skb);


int pkt_init(void);
void pkt_destroy(void);


__u8 get_traffic_class(struct ipv6hdr *hdr);
__be32 get_flow_label(struct ipv6hdr *hdr);
__u16 is_dont_fragment_set(struct iphdr *hdr);
__u16 is_more_fragments_set_ipv6(struct frag_hdr *hdr);
__u16 is_more_fragments_set_ipv4(struct iphdr *hdr);
__u16 is_dont_fragment_set(struct iphdr *hdr);
__u16 get_fragment_offset_ipv6(struct frag_hdr *hdr);
__u16 get_fragment_offset_ipv4(struct iphdr *hdr);
__be16 build_ipv6_frag_off_field(__u16 more_fragments, __u16 fragment_offset);
__be16 build_ipv4_frag_off_field(__u16 dont_fragment, __u16 more_fragments, __u16 fragment_offset);


struct fragment {
	struct sk_buff *skb;
	struct dst_entry *dst;

	struct {
		enum l3_proto proto;
		int len;
		void *ptr;
		bool ptr_needs_kfree;
	} l3_hdr;

	struct {
		enum l4_proto proto;
		int len;
		void *ptr;
		bool ptr_needs_kfree;
	} l4_hdr;

	struct {
		int len;
		void *ptr;
		bool ptr_needs_kfree;
	} payload;

	/** De la lista de packet.fragments. */
	struct list_head next;
};

enum verdict frag_create_ipv6(struct sk_buff *skb, struct fragment **frag_out);
enum verdict frag_create_ipv4(struct sk_buff *skb, struct fragment **frag_out);
void frag_init(struct fragment *);
enum verdict frag_create_skb(struct fragment *);

struct ipv6hdr *frag_get_ipv6_hdr(struct fragment *);
struct frag_hdr *frag_get_fragment_hdr(struct fragment *frag);
struct iphdr *frag_get_ipv4_hdr(struct fragment *);
struct tcphdr *frag_get_tcp_hdr(struct fragment *);
struct udphdr *frag_get_udp_hdr(struct fragment *);
struct icmp6hdr *frag_get_icmp6_hdr(struct fragment *);
struct icmphdr *frag_get_icmp4_hdr(struct fragment *);
unsigned char *frag_get_payload(struct fragment *);

void frag_print(struct fragment *frag);

void frag_kfree(struct fragment *);

struct packet {
	struct list_head fragments;
	struct fragment *first_fragment; /* TODO recordatorio: No hemos seteado esto en el de salida. */

	/** Si es cero, no sabemos todavía el tamaño total. */
	u16 total_bytes;
	u16 current_bytes;
	u32 fragment_id;
	/* In milliseconds. */
	unsigned int dying_time;

	struct list_head pkt_list_node;
};

unsigned int pkt_get_fragment_timeout(void);
void pkt_add_frag_ipv6(struct packet *pkt, struct fragment *frag);
void pkt_add_frag_ipv4(struct packet *pkt, struct fragment *frag);
struct packet *pkt_create_ipv6(struct fragment *frag);
struct packet *pkt_create_ipv4(struct fragment *frag);
bool pkt_is_complete(struct packet *pkt);
void pkt_kfree(struct packet *pkt, bool free_pkt);

inline enum l3_proto pkt_get_l3proto(struct packet *pkt);
inline enum l4_proto pkt_get_l4proto(struct packet *pkt);
inline void pkt_get_ipv4_src_addr(struct packet *pkt, struct in_addr *result);
inline void pkt_get_ipv4_dst_addr(struct packet *pkt, struct in_addr *result);
inline struct in6_addr *pkt_get_ipv6_src_addr(struct packet *pkt);
inline struct in6_addr *pkt_get_ipv6_dst_addr(struct packet *pkt);

#endif /* _NF_NAT64_PACKET_H */
