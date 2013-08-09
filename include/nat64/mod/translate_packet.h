#ifndef _NF_NAT64_TRANSLATING_THE_PACKET_H
#define _NF_NAT64_TRANSLATING_THE_PACKET_H

/**
 * @file
 * Fourth step of the Nat64 translation algorithm: "Translating the Packet", as defined in RFC6146
 * section 3.7.
 *
 * @author Alberto Leiva
 */

#include <linux/skbuff.h>
#include <linux/ip.h>
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/packet.h"


/**
 * An accesor for the full unused portion of the ICMP header, which I feel is missing from
 * linux/icmp.h.
 */
#define icmp4_unused un.gateway


int translate_packet_init(void);
void translate_packet_destroy(void);

int clone_translate_config(struct translate_config *clone);
int set_translate_config(__u32 operation, struct translate_config *new_config);

/**
 * Assumes "skb_in" is a IPv4 packet, and stores a IPv6 equivalent in "skb_out".
 *
 * @param tuple translated addresses from "skb_in".
 * @param skb_in the incoming packet.
 * @param skb_out out parameter, where the outgoing packet will be placed.
 */
bool translating_the_packet_4to6(struct tuple *tuple, struct packet *pkt_in,
		struct packet **pkt_out);
/**
 * Assumes "skb_in" is a IPv6 packet, and stores a IPv4 equivalent in "skb_out".
 *
 * @param tuple translated addresses from "skb_in".
 * @param skb_in the incoming packet.
 * @param skb_out out parameter, where the outgoing packet will be placed.
 */
bool translating_the_packet_6to4(struct tuple *tuple, struct packet *pkt_in,
		struct packet **pkt_out);

/**
 * Interprets in.payload as an independent packet, translates its layer 3 header (using
 * "l3_hdr_function") and places the result in out.payload.
 */
enum verdict translate_inner_packet(struct fragment *in_outer, struct fragment *out_outer,
		enum verdict (*l3_function)(struct tuple *, struct fragment *, struct fragment *));

__be16 icmp4_minimum_mtu(__u32 packet_mtu, __u16 in_mtu, __u16 out_mtu);
__be32 icmp6_minimum_mtu(__u16 packet_mtu, __u16 in_mtu, __u16 out_mtu, __u16 tot_len_field);

__u16 is_dont_fragment_set(struct iphdr *hdr);

#endif /* _NF_NAT64_TRANSLATING_THE_PACKET_H */
