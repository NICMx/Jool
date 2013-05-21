#ifndef _NF_NAT64_DETERMINE_INCOMING_TUPLE_H
#define _NF_NAT64_DETERMINE_INCOMING_TUPLE_H

/**
 * @file
 * The first step in the packet processing algorithm defined in the RFC.
 * The 3.4 section of RFC 6146 is encapsulated in this module.
 * Creates a tuple (summary) of the incoming packet.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva  <- maintenance
 */

#include <linux/skbuff.h>
#include "nat64/comm/types.h"


/**
 * Extracts the relevant data from "skb" and stores it in the "tuple" tuple.
 *
 * @param skb packet the data will be extracted from.
 * @param tuple this function will initialize *tuple as a pointer to conntrack's tuple for skb.
 * @return "true" if the tuple could be created, "false" otherwise.
 */
bool determine_in_tuple(struct sk_buff *skb, struct tuple *tuple);


#endif /* _NF_NAT64_DETERMINE_INCOMING_TUPLE_H */
