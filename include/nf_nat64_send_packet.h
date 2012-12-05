#ifndef _NF_NAT64_SEND_PACKET_H
#define _NF_NAT64_SEND_PACKET_H

#include <linux/skbuff.h>


bool nat64_send_packet_ipv4(struct sk_buff *skb);
bool nat64_send_packet_ipv6(struct sk_buff *skb);


#endif /* _NF_NAT64_SEND_PACKET_H */
