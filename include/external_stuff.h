#ifndef _NF_NAT64_EXTERNAL_STUFF_H
#define _NF_NAT64_EXTERNAL_STUFF_H

#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/in6.h>

#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_tuple.h>


void nat64_send_icmp_error(struct sk_buff *packet, __u8 type, __u8 code);

bool is_address_legal(struct in6_addr *address);
bool nf_nat64_ipv4_pool_contains_addr(__be32 addr);
bool nf_nat64_ipv6_pool_contains_addr(struct in6_addr *addr);

bool nat64_filtering_and_updating(struct nf_conntrack_tuple *tuple_in);
bool nat64_determine_outgoing_tuple(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out);
bool nat64_send_packet(struct sk_buff *skb_out);


#endif
