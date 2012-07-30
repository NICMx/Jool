#ifndef _NF_NAT64_TRANSLATE_PACKET_H
#define _NF_NAT64_TRANSLATE_PACKET_H

/**
 * Fourth and last step of the Nat64 translation algorithm: "Translating the
 * Packet", as defined in RFC6146 section 3.7.
 */

#include <linux/types.h>
#include <net/netfilter/nf_nat_protocol.h>

/**
 * Entry point; the only function that needs to be public.
 *
 * Using the "l3protocol" layer 3 protocol, the "l4protocol" layer 4
 * protocol, and assuming that the "skb" incoming packet brought about the
 * "outgoing" tuple, returns the packet the Nat64 should send to the
 * outgoing network.
 *
 * If "skb" (the incoming packet) was a hairpin packet, set "hairpin" as
 * "true".
 *
 * The whole 3.7 section of RFC 6146 is encapsulated in this function.
 */
struct sk_buff * nat64_translate_packet(u_int8_t l3protocol,
        u_int8_t l4protocol, struct sk_buff *skb,
        struct nf_conntrack_tuple * outgoing, bool hairpin);

#endif /* _NF_NAT64_TRANSLATE_PACKET_H */

