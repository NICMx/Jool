#include "nat64/mod/icmp_wrapper.h"

#include <net/icmp.h>
#include <linux/icmpv6.h>

void icmp4_send(struct sk_buff *skb, int type, int code, __be32 info)
{
	if (skb && skb->dev)
		icmp_send(skb, type, code, info);
}

void icmp6_send(struct sk_buff *skb, u8 type, u8 code, __u32 info)
{
	if (skb && skb->dev)
		icmpv6_send(skb, type, code, info);
}
