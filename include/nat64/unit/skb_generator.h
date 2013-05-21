#include <linux/skbuff.h>
#include "nat64/comm/types.h"

int create_skb_ipv6_udp(struct ipv6_pair *pair6, struct sk_buff **result);
int create_skb_ipv6_tcp(struct ipv6_pair *pair6, struct sk_buff **result);
int create_skb_ipv6_icmp(struct ipv6_pair *pair6, struct sk_buff **result);
int create_skb_ipv4_udp(struct ipv4_pair *pair4, struct sk_buff **result);
int create_skb_ipv4_tcp(struct ipv4_pair *pair4, struct sk_buff **result);
int create_skb_ipv4_icmp(struct ipv4_pair *pair4, struct sk_buff **result);
