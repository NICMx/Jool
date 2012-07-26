#ifndef _NF_NAT64_TUPLE_HANDLING_H
#define _NF_NAT64_TUPLE_HANDLING_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack_tuple.h>

extern int ipv6_pref_len;
extern struct in_addr ipv4_pool_range_first;
extern struct in_addr ipv4_pool_range_last;

static bool nat64_filtering_and_updating(u_int8_t l3protocol, u_int8_t l4protocol, 
	struct sk_buff *skb, struct nf_conntrack_tuple * inner);
	
static struct nf_conntrack_tuple * nat64_determine_outgoing_tuple(
	u_int8_t l3protocol, u_int8_t l4protocol, struct sk_buff *skb, 
	struct nf_conntrack_tuple * inner,
	struct nf_conntrack_tuple * outgoing);

static bool nat64_got_hairpin(u_int8_t l3protocol, struct nf_conntrack_tuple * outgoing);
	
static struct nf_conntrack_tuple * nat64_hairpinning_and_handling(u_int8_t l4protocol, 
	struct nf_conntrack_tuple * inner,
	struct nf_conntrack_tuple * outgoing);

#endif
