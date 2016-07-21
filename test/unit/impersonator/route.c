#include "nat64/mod/common/route.h"
#include "nat64/common/types.h"

struct dst_entry *__route4(struct net *ns, __be32 daddr, __u8 tos, __u8 proto,
		__u32 mark, struct sk_buff *skb)
{
	log_debug("Pretending I'm routing an IPv4 packet.");
	return NULL;
}

struct dst_entry *route4(struct net *ns, struct packet *pkt)
{
	log_debug("Pretending I'm routing an IPv4 packet.");
	return NULL;
}

struct dst_entry *route6(struct net *ns, struct packet *pkt)
{
	log_debug("Pretending I'm routing an IPv6 packet.");
	return NULL;
}
