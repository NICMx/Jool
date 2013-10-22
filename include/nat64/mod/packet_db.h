#ifndef _NF_NAT64_PACKET_DB_H
#define _NF_NAT64_PACKET_DB_H

#include "nat64/mod/packet.h"


/**
 * @file
 * Jool's main packet store.
 *
 * As usual, fragments are a pain in the ass. Only the first one contains layer-4 headers, and
 * NAT64 is a network + transport hybrid like much networking technology today. Normally, firewalls
 * and average NAT can get away with it by reassembling fragments upon arrival, but that is
 * undersirable here for a number of reasons:
 * - It'd be a hack. IPv6 routers don't fragment and as far as I know, conntrack's defrag doesn't
 *   return me the original fragments' size. If we assemble, how do we compute the path's MTU
 *   without path MTU discovery while refragmenting? Otherwise we could become a black hole.
 * - Separate fragment processing is the natural NAT64 way as described by RFC6146 (see section
 *   3.4).
 * - Assembling-and-refragmenting is needless copying around (i. e. slow) and we're in a botton half
 *   (not that this doesn't affect other technologies, and Jool is not yet balls-to-the-wall fast,
 *   but it's there).
 *
 * So what are we supposed to do? Store the fragments as they arrive until we have enough
 * information to translate them (i. e. the first fragment, which contains the transport headers),
 * and then translate them (separately, but all based on the first one).
 *
 * TODO What we actually do currently is store the fragments until they have all arrived, and then
 * translate them. I don't think this is as bad as it sounds since the default arrival tolerance is
 * only two seconds, but the to-do is there anyway.
 *
 * This module is the database that stores the fragments still waiting for their siblings. Hence,
 * I'm in a bit of a conundrum as to whether it should be called "pktdb" or "fragdb". As it stands,
 * the former won since (to the eyes of the rest of the modules) pkt_from_skb() actually returns
 * packets, not fragments.
 */


/**
 * Call during initialization for the remaining functions to work properly.
 */
int pktdb_init(void);

/**
 * Computes "skb"'s struct fragment, infers whether it is part of a larger packet, and stores it in
 * the database if it has siblings that haven't arrived yet. If they have all arrived, or if skb is
 * already whole, then it returns the resulting struct packet.
 *
 * pkt should point to allocated memory (heap vs stack doesn't matter). It should not be initialized
 * (that's the job of this function).
 */
verdict pkt_from_skb(struct sk_buff *skb, struct packet **pkt);

/**
 * Empties the database, freeing memory. Call during destruction to avoid memory leaks.
 */
void pktdb_destroy(void);


#endif /* _NF_NAT64_PACKET_DB_H */
