#ifndef _JOOL_UNIT_SKB_GENERATOR_H
#define _JOOL_UNIT_SKB_GENERATOR_H

#include "nat64/mod/packet.h"
#include "nat64/mod/types.h"


int init_ipv6_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple6,
		bool df, bool mf, u16 frag_offset);
int init_ipv4_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple4,
		bool df, bool mf, u16 frag_offset);
int init_tcp_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, struct tuple *tuple);
int ipv6_tcp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple6);
int ipv4_tcp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple4);
int init_payload_normal(void *l4_hdr, u16 payload_len);

int create_skb_ipv6_udp(struct tuple *tuple6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_tcp(struct tuple *tuple6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_icmp_info(struct tuple *tuple6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_icmp_error(struct tuple *tuple6, struct sk_buff **result, u16 payload_len);

int create_skb_ipv4_udp(struct tuple *tuple4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_tcp(struct tuple *tuple4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_icmp_info(struct tuple *tuple4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_icmp_error(struct tuple *tuple4, struct sk_buff **result, u16 payload_len);

int create_skb_ipv4_udp_frag(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset);
int create_skb_ipv4_tcp_frag(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset);
int create_skb_ipv4_icmp_info_frag(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset);
/* fragmented ICMPv4 errors do not exist. */

int create_skb_ipv6_udp_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool mf, u16 frag_offset);
int create_skb_ipv6_tcp_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool mf, u16 frag_offset);
int create_skb_ipv6_icmp_info_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool mf, u16 frag_offset);
/* fragmented ICMPv6 errors do not exist. */

int create_packet_ipv4_udp_fragmented_disordered(struct tuple *tuple4, struct sk_buff **skb_out);
int create_packet_ipv6_tcp_fragmented_disordered(struct tuple *tuple6, struct sk_buff **skb_out);

int create_tcp_packet(struct sk_buff **skb, l3_protocol l3_proto, bool syn, bool rst, bool fin);

#endif /* _JOOL_UNIT_SKB_GENERATOR_H */
