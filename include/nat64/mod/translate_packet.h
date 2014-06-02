#ifndef _NF_NAT64_TRANSLATING_THE_PACKET_H
#define _NF_NAT64_TRANSLATING_THE_PACKET_H

/**
 * @file
 * Fourth step of the Nat64 translation algorithm: "Translating the Packet", as defined in RFC6146
 * section 3.7.
 *
 * @author Alberto Leiva
 */

#include <linux/skbuff.h>
#include <linux/ip.h>
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/packet.h"


/**
 * An accesor for the full unused portion of the ICMP header, which I feel is missing from
 * linux/icmp.h.
 */
#define icmp4_unused un.gateway


int translate_packet_init(void);
void translate_packet_destroy(void);

int clone_translate_config(struct translate_config *clone);
int set_translate_config(__u32 operation, struct translate_config *new_config);

/**
 * Warning: if the translated packet is too big and the situation demands it (IPv4 to IPv6 and no
 * DF), "output" will be fragmented. Its pieces will be queued in order in (*output)->next.
 * Keep that in mind when you release or send "output".
 */
verdict translating_the_packet(struct tuple *tuple, struct sk_buff *in, struct sk_buff **output);


#endif /* _NF_NAT64_TRANSLATING_THE_PACKET_H */
