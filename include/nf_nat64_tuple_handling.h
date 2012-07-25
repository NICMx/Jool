#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack_tuple.h>
/*
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>

#include <linux/netdevice.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ipv6.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#include <linux/timer.h>
#include <linux/jhash.h>
#include <linux/rcupdate.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_protocol.h>
*/
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
