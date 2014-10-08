#ifndef _JOOL_MOD_INCOMING_H
#define _JOOL_MOD_INCOMING_H

/**
 * @file
 * The first step in the packet processing algorithm defined in the RFC.
 * The 3.4 section of RFC 6146 is encapsulated in this module.
 * Creates a tuple (summary) of the incoming packet.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

#include "nat64/mod/types.h"

verdict determine_in_tuple(struct sk_buff *skb, struct tuple *in_tuple);


#endif /* _JOOL_MOD_INCOMING_H */
