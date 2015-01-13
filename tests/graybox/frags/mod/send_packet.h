#ifndef FRAGS_MOD_SEND_PACKET_H
#define FRAGS_MOD_SEND_PACKET_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include "types.h"


/**
 * One-liner for filling up a 'flowi' and then calling the kernel's IPv4
 * routing function.
 *
 * Routes the skb described by the arguments. Returns the 'destination entry'
 * the kernel needs to know which interface the skb should be forwarded
 * through.
 */
struct dst_entry *route_ipv4(struct iphdr *hdr_ip);

/**
 * Same as route_ipv4(), except for IPv6.
 */
struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip);


#endif /* FRAGS_MOD_SEND_PACKET_H */
