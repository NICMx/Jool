#ifndef _NF_NAT64_ICMP_WRAPPER_H
#define _NF_NAT64_ICMP_WRAPPER_H

#include <linux/types.h>
#include <linux/skbuff.h>


void icmp4_send(struct sk_buff *skb, int type, int code, __be32 info);
void icmp6_send(struct sk_buff *skb, u8 type, u8 code, __u32 info);


#endif /* _NF_NAT64_ICMP_WRAPPER_H */
