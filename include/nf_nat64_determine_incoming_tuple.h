#ifndef _NF_NAT64_DETERMINE_INCOMING_TUPLE_H
#define _NF_NAT64_DETERMINE_INCOMING_TUPLE_H

#include <net/netfilter/nf_conntrack_core.h>

/**
 * Initializes this module. Please call once before using
 * nat64_determine_incoming_tuple().
 */
bool nat64_determine_incoming_tuple_init(void);

/**
 * The 3.4 section of RFC 6146 is encapsulated in this function.
 *
 * Using the "l3protocol" layer 3 protocol and the "l4protocol" layer 4
 * protocol, extracts the relevant data from "skb" and stores it in "inner".
 */
bool nat64_determine_incoming_tuple(u_int8_t l3protocol, u_int8_t l4protocol,
        struct sk_buff *skb, struct nf_conntrack_tuple *inner);

/**
 * Terminates this module. Please call once at the end of the program so
 * memory can be released.
 */
void nat64_determine_incoming_tuple_destroy(void);

#endif /* _NF_NAT64_DETERMINE_INCOMING_TUPLE_H */
