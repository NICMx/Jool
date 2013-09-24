#include <linux/skbuff.h>
#include "nat64/comm/types.h"


int init_ipv6_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, void *arg);
int init_ipv4_hdr(void *l3_hdr, u16 payload_len, u8 nexthdr, void *arg);
int init_tcp_hdr(void *l4_hdr, int l3_hdr_type, u16 datagram_len, void *arg);
int ipv6_tcp_post(void *l4_hdr, u16 datagram_len, void *arg);
int ipv4_tcp_post(void *l4_hdr, u16 datagram_len, void *arg);
int init_payload_normal(void *l4_hdr, u16 payload_len);

int create_skb_ipv6_udp(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_tcp(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_icmp_info(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_icmp_error(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);

int create_skb_ipv4_udp(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_tcp(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_icmp_info(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_icmp_error(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len);

int create_skb_ipv4_udp_fragment(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_tcp_fragment(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len);
int create_skb_ipv4_icmp_info_fragment(struct ipv4_pair *pair4, struct sk_buff **result, u16 payload_len);
/* fragmented ICMPv4 errors do not exist. */

int create_skb_ipv6_udp_fragment_1(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_udp_fragment_n(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_tcp_fragment_1(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_tcp_fragment_n(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_icmp_info_fragment_1(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
int create_skb_ipv6_icmp_info_fragment_n(struct ipv6_pair *pair6, struct sk_buff **result, u16 payload_len);
/* fragmented ICMPv6 errors do not exist. */
