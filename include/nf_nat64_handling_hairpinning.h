#ifndef _NF_NAT64_HANDLING_HARPINNING_H
#define _NF_NAT64_HANDLING_HARPINNING_H

#include <net/netfilter/nf_conntrack_tuple.h>


/**
 * nat64_got_hairpin - checks whether a packet is a hairpin packet
 * @param outgoing the outgoing tuple
 * @return boolean value to know if the packet's a hairpin packet
 *
 * It checks whether a packet has a destinatio address that is within 
 * the range configured in the IPv4 pool
 *
 */
bool nat64_got_hairpin(struct nf_conntrack_tuple *outgoing);


#endif /* _NF_NAT64_HANDLING_HARPINNING_H */
