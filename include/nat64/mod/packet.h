#ifndef _NF_NAT64_PACKET_H
#define _NF_NAT64_PACKET_H

#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
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
	VER_DROP = NF_DROP
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


struct fragment {
	struct sk_buff *skb;

	struct {
		enum l3_proto proto;
		int len;
		void *ptr;
		bool ptr_belongs_to_skb;
	} l3_hdr;

	struct {
		enum l4_proto proto;
		int len;
		void *ptr;
		bool ptr_belongs_to_skb;
	} l4_hdr;

	struct {
		int len;
		void *ptr;
		bool ptr_belongs_to_skb;
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

void frag_kfree(struct fragment *);

struct packet {
	struct list_head fragments;

	/** Si es cero, no sabemos todavía el tamaño total. */
//	u16 total_bytes;
//	u16 current_bytes;
//	u32 fragment_id;
//	unsigned int dying_time;

//	// TODO recordatorio: No hemos seteado esto en el de salida.
//	enum l4_proto proto;
//	union {
//		struct {
//			struct in6_addr src, dst;
//		} ipv6;
//		struct {
//			struct in_addr src, dst;
//		} ipv4;
//	} addr;
//	u16 src_port, dst_port;
};

void pkt_add_skb(struct packet *pkt, struct sk_buff *skb);
bool pkt_is_complete(struct packet *pkt);

void pkt_kfree(struct packet *);

#endif /* _NF_NAT64_PACKET_H */
