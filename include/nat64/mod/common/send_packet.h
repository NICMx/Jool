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

#include "nat64/mod/common/types.h"

/**
 * Puts "out_skb" on the network.
 * You need to have routed out_skb first (see route.h).
 *
 * For "out_skb" to be valid, setting the following fields is known to be necessary:
 * -> data, head, len, data_len, end, network_header and dev.
 * Also probably:
 * -> tail, transport_header and _skb_refdst.
 * If you want to place more kernel modules on netfilter's postrouting hook, you might need to set
 * more.
 *
 * Note that this function inherits from ip_local_out() and ip6_local_out() the annoying side
 * effect of freeing "out_skb", EVEN IF IT COULD NOT BE SENT.
 *
 * On stateful operation, in_skb is used to hack fragmentation neededs if necessary. On stateless
 * operation, in_skb isn't used for anything. TODO (fine) Do something about it?
 */
verdict sendpkt_send(struct sk_buff *in_skb, struct sk_buff *out_skb);


#endif /* _JOOL_MOD_SEND_PACKET_H */
