#ifndef _NF_NAT64_OUTGOING_H
#define _NF_NAT64_OUTGOING_H

/**
 * @file
 * Third step in the packet processing algorithm defined in the RFC.
 * The 3.4 section of RFC 6146 is encapsulated in this module.
 * Infers a tuple (summary) of the outgoing packet, yet to be created.
 *
 * @author Ramiro Nava
 * @author Alberto Leiva  <- maintenance
 */

#include <linux/skbuff.h>
#include "nat64/comm/types.h"


bool compute_out_tuple_6to4(struct tuple *in, struct sk_buff *skb_in, struct tuple *out);
bool compute_out_tuple_4to6(struct tuple *in, struct sk_buff *skb_in, struct tuple *out);

#endif /* _NF_NAT64_OUTGOING_H */
