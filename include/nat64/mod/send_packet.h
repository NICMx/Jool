#ifndef _NF_NAT64_SEND_PACKET_H
#define _NF_NAT64_SEND_PACKET_H

/**
 * @file
 * Functions to artificially send homemade packets through the interfaces. Basically, you initialize
 * the data portion of a sk_buff and this worries about putting it on the network.
 *
 * We need this because the kernel assumes that when a packet enters a module, a packet featuring
 * the same layer-3 protocol exits the module. So we can't just morph IPv4 packets into IPv6 ones
 * and vice-versa; we need to ask the kernel to drop the original packets and send new ones on our
 * own.
 *
 * These are based on Ecdysis's functions for the same purpose.
 */

#include <linux/types.h>
#include <linux/skbuff.h>


/**
 * Assumes "skb" contains a IPv4 packet, and sends it.
 *
 * For skb to be valid, setting the following fields is known to be neccesary:
 * -> data, head, len, data_len, end and network_header.
 * Also probably:
 * -> tail and transport_header
 * Probably not:
 * -> mac_header.
 * If you want to place more kernel modules on netfilter's postrouting hook, you probably need to
 * set more.
 *
 * Please note that this function inherits from ip_local_out() the idiotic side effect of freeing
 * "skb", EVEN IF IT COULD NOT BE SENT.
 */
bool send_packet_ipv4(struct sk_buff *skb_in, struct sk_buff *skb_out);

/**
 * Assumes "skb" contains a IPv6 packet, and sends it.
 *
 * For skb to be valid, setting the following fields is known to be neccesary:
 * -> data, head, len, data_len, end and network_header.
 * Also probably:
 * -> tail and transport_header
 * Probably not:
 * -> mac_header.
 * If you want to place more kernel modules on netfilter's postrouting hook, you probably need to
 * set more.
 *
 * Please note that this function inherits from ip6_local_out() the idiotic side effect of freeing
 * "skb", EVEN IF IT COULD NOT BE SENT.
 */
bool send_packet_ipv6(struct sk_buff *skb_in, struct sk_buff *skb_out);




#endif /* _NF_NAT64_SEND_PACKET_H */
