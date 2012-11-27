#ifndef _NF_NAT64_EXTERNAL_STUFF_H
#define _NF_NAT64_EXTERNAL_STUFF_H

#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/in6.h>

#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_tuple.h>


struct configuration
{
	/**
	 * The user's reserved head room in bytes. Default should be 0.
	 * Can be negative, if the user wants to compensate for the LL_MAX_HEADER constant.
	 * (LL_MAX_HEADER = the kernel's reserved head room + l2 header's length.)
	 */
	__u16 packet_head_room;
	/** I suggest default = 32 bytes. */
	__u16 packet_tail_room;

	bool override_ipv6_traffic_class;
	/** Default should be false. */
	bool override_ipv4_traffic_class;
	__u8 ipv4_traffic_class;
	/** Default should be true. */
	bool df_always_set;

	/** Default should be false. */
	bool generate_ipv4_id;

	/** Default should be true; in fact I don't see why anyone would want it to be false. */
	bool improve_mtu_failure_rate;
	// TODO (info) there should probably be a way to compute these two values by ourselves.
	__u16 ipv6_nexthop_mtu;
	__u16 ipv4_nexthop_mtu;
	__u16 out_mtu;

	/** Default values are { 65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68 }. */
	__u16 *mtu_plateaus;
	/** Length of the mtu_plateaus array. */
	__u16 mtu_plateau_count;
};

extern struct configuration config;


void nat64_send_icmp_error(struct sk_buff *packet, __u8 type, __u8 code);

bool is_address_legal(struct in6_addr *address);
bool nf_nat64_ipv4_pool_contains_addr(__be32 addr);
bool nf_nat64_ipv6_pool_contains_addr(struct in6_addr *addr);

bool nat64_determine_incoming_tuple(struct sk_buff* skb_in, struct nf_conntrack_tuple **tuple_in);
bool nat64_filtering_and_updating(struct nf_conntrack_tuple *tuple_in);
bool nat64_determine_outgoing_tuple(struct nf_conntrack_tuple *tuple_in,
		struct nf_conntrack_tuple **tuple_out);
bool nat64_hairpinning_and_handling(struct nf_conntrack_tuple *tuple_out, struct sk_buff *skb_out);
bool nat64_send_packet(struct sk_buff *skb_out);


#endif
