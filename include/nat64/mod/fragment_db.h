#ifndef _JOOL_MOD_FRAGMENT_DB_H
#define _JOOL_MOD_FRAGMENT_DB_H

/**
 * @file
 * Jool's fragment queuer. It is mostly RFC 815, adapted to the requirement of only correlating
 * (never assembling) fragments.
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
 * TODO (performance) What we actually do currently is store the fragments until they have all
 * arrived, and then translate them. I don't think this is as bad as it sounds since the default
 * arrival tolerance is only two seconds and never gets updated, but the to-do is there anyway.
 *
 * This module is the database that stores the fragments still waiting for their siblings.
 */

#include "nat64/mod/types.h"
#include "nat64/comm/config_proto.h"


int fragdb_init(void);

int fragdb_set_config(enum fragmentation_type type, size_t size, void *value);
int fragdb_clone_config(struct fragmentation_config *clone);

verdict fragdb_handle6(struct sk_buff *skb_in, struct sk_buff **skb_out);

void fragdb_destroy(void);


#endif /* _JOOL_MOD_FRAGMENT_DB_H */
