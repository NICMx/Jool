#ifndef _NF_NAT64_SEND_PACKET_H
#define _NF_NAT64_SEND_PACKET_H

/**
 * @file
 * Functions to artificially send homemade packets through the interfaces. Basically, you initialize
 * sk_buffs and this worries about putting them on the network.
 *
 * We need this because the kernel assumes that when a packet enters a module, a packet featuring
 * the same layer-3 protocol exits the module. So we can't just morph IPv4 packets into IPv6 ones
 * and vice-versa; we need to ask the kernel to drop the original packets and send new ones on our
 * own.
 */

#include <linux/types.h>
#include "nat64/mod/packet.h"


/**
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4 routing function.
 *
 * Routes the skb described by the arguments. Returns the 'destination entry' the kernel needs
 * to know which interface the skb should be forwarded through.
 */
struct dst_entry *route_ipv4(struct iphdr *hdr_ip, void *l4_hdr, enum l4_proto l4proto, u32 mark);

/**
 * Same as route_ipv4(), except for IPv6.
 */
struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip, void *l4_hdr, enum l4_proto l4proto, u32 mark);

/**
 * Puts all of "pkt"'s skbs on the network.
 *
 * For the skbs to be valid, setting the following fields is known to be neccesary:
 * -> data, head, len, data_len, end, network_header and dev.
 * Also probably:
 * -> tail, transport_header and _skb_refdst.
 * If you want to place more kernel modules on netfilter's postrouting hook, you probably need to
 * set more.
 *
 * Note that this function inherits from ip_local_out() and ip6_local_out() the annoying side
 * effect of freeing the skbs, EVEN IF THEY COULD NOT BE SENT.
 */
enum verdict send_pkt(struct packet *pkt);


#endif /* _NF_NAT64_SEND_PACKET_H */
