#ifndef _JOOL_UNIT_SKB_GENERATOR_H
#define _JOOL_UNIT_SKB_GENERATOR_H

#include "nat64/common/types.h"
#include "nat64/mod/common/packet.h"

typedef int (*skb_creator)(struct tuple *, struct sk_buff **, u16, u8);
typedef int (*skb_frag_creator)(struct tuple *, struct sk_buff **, u16, u16, bool, bool, u16, u8);

int init_ipv6_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple6,
		bool df, bool mf, u16 frag_offset, u8 ttl);
int init_ipv4_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, struct tuple *tuple4,
		bool df, bool mf, u16 frag_offset, u8 ttl);
int init_tcp_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, struct tuple *tuple);
int ipv6_tcp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple6);
int ipv4_tcp_post(void *l4_hdr, u16 datagram_len, struct tuple *tuple4);
int init_payload_normal(void *l4_hdr, u16 payload_len);

int create_skb6_upd_custom_payload(struct tuple *tuple6, struct sk_buff **result, u16 *payload_array,
		u16 payload_len, u8 ttl);
int create_skb4_upd_custom_payload(struct tuple *tuple4, struct sk_buff **result, u16 *payload_array,
		u16 payload_len, u8 ttl);
int create_skb6_udp(struct tuple *tuple6, struct sk_buff **result, u16 payload_len, u8 ttl);
int create_skb6_tcp(struct tuple *tuple6, struct sk_buff **result, u16 payload_len, u8 ttl);
int create_skb6_icmp_info(struct tuple *tuple6, struct sk_buff **result, u16 payload_len, u8 ttl);
int create_skb6_icmp_error(struct tuple *tuple6, struct sk_buff **result, u16 payload_len, u8 ttl);

int create_skb4_udp(struct tuple *tuple4, struct sk_buff **result, u16 payload_len, u8 ttl);
int create_skb4_tcp(struct tuple *tuple4, struct sk_buff **result, u16 payload_len, u8 ttl);
int create_skb4_icmp_info(struct tuple *tuple4, struct sk_buff **result, u16 payload_len, u8 ttl);
int create_skb4_icmp_error(struct tuple *tuple4, struct sk_buff **result, u16 payload_len, u8 ttl);

int create_skb4_udp_frag(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl);
int create_skb4_tcp_frag(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl);
int create_skb4_icmp_info_frag(struct tuple *tuple4, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl);
/* fragmented ICMPv4 errors do not exist. */

int create_skb6_udp_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl);
int create_skb6_tcp_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl);
int create_skb6_icmp_info_frag(struct tuple *tuple6, struct sk_buff **result, u16 payload_len,
		u16 total_l4_len, bool df, bool mf, u16 frag_offset, u8 ttl);
/* fragmented ICMPv6 errors do not exist. */

int create_tcp_packet(struct sk_buff **skb, l3_protocol l3_proto, bool syn, bool rst, bool fin);


#endif /* _JOOL_UNIT_SKB_GENERATOR_H */
