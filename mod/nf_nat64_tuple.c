#include <net/ipv6.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#include <net/netfilter/nf_conntrack_tuple.h>

#include "nf_nat64_tuple.h"

struct nf_conntrack_tuple * nat64_outfunc4_icmpv6(union nf_inet_addr src, 
		u_int16_t srcport,union nf_inet_addr dst, u_int16_t dstport, 
		u_int8_t l3proto, u_int8_t l4proto)
{
	struct nf_conntrack_tuple * outgoing;
	memset(outgoing, 0, sizeof(* outgoing));
	
	return outgoing;
}
