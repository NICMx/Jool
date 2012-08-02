#ifndef _NF_NAT64_TUPLE_HANDLING_H
#define _NF_NAT64_TUPLE_HANDLING_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack_tuple.h>

/**
 * nat64_filtering_and_updating - implements step 3.5 from the RFC6146
 * @param l3protocol type of layer 3 protocol
 * @param l4protocol type of layer 4 protocol
 * @param skb socket buffer 
 * @param inner incoming tuple
 * @return boolean value whether the function was processed without
 * errors o not
 *
 * It searches for the BIB and Session containing the IPv4 tuple
 * or searches for the BIB and Session containing the IPv6 tuple if
 * the function can't find the IPv6 tuple it creates a new Session
 * and BIB entry. 
 *
 */
bool nat64_filtering_and_updating(u_int8_t l3protocol, u_int8_t l4protocol,
        struct sk_buff *skb, struct nf_conntrack_tuple * inner);


/**
 * nat64_determine_outgoing_tuple - implementes step 3.6 from the RFC6146
 * @param l3protocol type of layer 3 protocol
 * @param l4protocol type of layer 4 protocol
 * @param skb socket buffer 
 * @param inner incoming tuple
 * @return outgoing tuple destined for the IPv4 or IPv6
 *
 * It searches the BIB and Session tables for the corresponding entry that matches
 * the incoming tuple and generates the outgoing tuple.
 *
 */
struct nf_conntrack_tuple
        *nat64_determine_outgoing_tuple(u_int8_t l3protocol,
                u_int8_t l4protocol, struct sk_buff *skb,
                struct nf_conntrack_tuple * inner);

/**
 * nat64_got_hairpin - checks whether a packet is a hairpin packet
 * @param l3protocol type of layer 3 protocol
 * @param outgoing outgoing tuple
 * @return boolean value to know if the packet's a hairpin packet
 *
 * It checks whether a packet has a destinatio address that is within 
 * the range configured in the IPv4 pool
 *
 */
bool nat64_got_hairpin(u_int8_t l3protocol,
        struct nf_conntrack_tuple * outgoing);

/**
 * nat64_hairpinning_and_handling - implementes step 3.8 from the RFC6146
 * @param l4protocol type of layer 4 protocol
 * @param inner incoming tuple
 * @param outgoing outgoing tuple
 * @return outgoing tuple to perform a U-turn in the network
 *
 * It performs hairpinning, it recieves an IPv6 tuple and returns
 * an IPv6 tuple destined to another host in the network if said host
 * is found in the BIB and Session tables.
 */
struct nf_conntrack_tuple
        *nat64_hairpinning_and_handling(u_int8_t l4protocol,
                struct nf_conntrack_tuple * inner,
                struct nf_conntrack_tuple * outgoing);

#endif /* _NF_NAT64_TUPLE_HANDLING_H */
