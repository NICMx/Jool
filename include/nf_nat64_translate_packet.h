/**
 * Fourth and last step of the Nat64 translation algorithm: "Translating the
 * Packet", as defined in RFC6146 section 3.7.
 */

#ifndef _NF_NAT64_TRANSLATE_PACKET_H
#define _NF_NAT64_TRANSLATE_PACKET_H

#include <linux/types.h>
#include <net/netfilter/nf_nat_protocol.h>

/**
 * Transport layer protocols allowed by the NAT64 implementation when the
 * network protocol is IPv4.
 * TODO Esta realmente no la usamos. La copiamos aquí porque venía con la de
 * abajo; Probablemente va a terminar en otro lado.
 */
#define NAT64_IP_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMP)
/**
 * Transport layer protocols allowed by the NAT64 implementation when the
 * network protocol is IPv6.
 * TODO Esta también se usa en otra parte. Probablemente va a acabar definida
 * en otro .h.
 */
#define NAT64_IPV6_ALLWD_PROTOS (IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMPV6)

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

#endif

