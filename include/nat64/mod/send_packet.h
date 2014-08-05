#ifndef _JOOL_MOD_SEND_PACKET_H
#define _JOOL_MOD_SEND_PACKET_H

/**
 * @file
 * Functions to artificially send homemade packets through the interfaces. Basically, you initialize
 * sk_buffs and this worries about putting them on the network.
 *
 * We need this because the kernel assumes that when a packet enters a module, a packet featuring
 * the same layer-3 protocol exits the module. So we can't just morph IPv4 packets into IPv6 ones
 * and vice-versa; we need to ask the kernel to drop the original packets and send new ones on our
 * own.
 *
 * @author Alberto Leiva
 */

#include <linux/types.h>
#include "nat64/mod/types.h"
#include "nat64/mod/packet.h"


/**
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4 routing function.
 *
 * Routes the skb described by the arguments. Returns the 'destination entry' the kernel needs
 * to know which interface the skb should be forwarded through.
 *
 * This function assumes "skb" isn't fragmented.
 */
int route_ipv4(struct sk_buff *skb);

/**
 * Same as route_ipv4(), except for IPv6.
 */
int route_ipv6(struct sk_buff *skb);

/**
 * Puts "skb" on the network.
 *
 * For "skb" to be valid, setting the following fields is known to be neccesary:
 * -> data, head, len, data_len, end, network_header and dev.
 * Also probably:
 * -> tail, transport_header and _skb_refdst.
 * If you want to place more kernel modules on netfilter's postrouting hook, you might need to set
 * more.
 *
 * Note that this function inherits from ip_local_out() and ip6_local_out() the annoying side
 * effect of freeing "skb", EVEN IF IT COULD NOT BE SENT.
 */
verdict send_pkt(struct sk_buff *skb);


#endif /* _JOOL_MOD_SEND_PACKET_H */
