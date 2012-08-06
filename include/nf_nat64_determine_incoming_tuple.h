#ifndef _NF_NAT64_DETERMINE_INCOMING_TUPLE_H
#define _NF_NAT64_DETERMINE_INCOMING_TUPLE_H

/**
 * @file
 * The first step in the packet processing algorithm defined in the RFC.
 * The 3.4 section of RFC 6146 is encapsulated in this module.
 */

#include <net/netfilter/nf_conntrack_core.h>

/**
 * Initializes this module. Please call once before using nat64_determine_incoming_tuple().
 *
 * @return "true" if the initialization was successful. "false" otherwise.
 */
bool nat64_determine_incoming_tuple_init(void);

/**
 * Using the "l3protocol" layer 3 protocol and the "l4protocol" layer 4 protocol, extracts the relevant data from "skb"
 * and stores it in "inner".
 *
 * @param l3protocol Either NFPROTO_IPV4 or NFPROTO_IPV6. Transport protocol "skb" is encoded in.
 * @param l4protocol Either IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP. Network protocol "skb" is encoded in.
 * @param skb packet the tuple will be generated from.
 * @param inner the tuple. This function will summarize "skb" here.
 * @return "true" if the tuple could be created, "false" otherwise.
 */
bool nat64_determine_incoming_tuple(u_int8_t l3protocol, u_int8_t l4protocol, struct sk_buff *skb,
        struct nf_conntrack_tuple *inner);

/**
 * Terminates this module. Please call once at the end of the program so memory can be released.
 */
void nat64_determine_incoming_tuple_destroy(void);

#endif /* _NF_NAT64_DETERMINE_INCOMING_TUPLE_H */
