#ifndef H_NF_NAT64_DETERMINE_INCOMING_TUPLE
#define H_NF_NAT64_DETERMINE_INCOMING_TUPLE

#include <net/netfilter/nf_conntrack_core.h>


/** The IPv4 protocol. */
struct nf_conntrack_l3proto * l3proto_ip __read_mostly;
/** The IPv6 protocol. */
struct nf_conntrack_l3proto * l3proto_ipv6 __read_mostly;

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

#endif
