#ifndef _NF_NAT64_OUTGOING_H
#define _NF_NAT64_OUTGOING_H

#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "nf_nat64_types.h"

bool compute_outgoing_tuple_6to4(struct nf_conntrack_tuple *in, struct sk_buff *skb_in,
		struct nf_conntrack_tuple *out);
bool compute_outgoing_tuple_4to6(struct nf_conntrack_tuple *in, struct sk_buff *skb_in,
		struct nf_conntrack_tuple *out);

#endif /* _NF_NAT64_OUTGOING_H */
