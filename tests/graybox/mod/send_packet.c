#include "send_packet.h"

#include <linux/icmp.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <net/flow.h>

#include "types.h"


struct dst_entry *route_ipv4(struct iphdr *hdr)
{
	struct flowi4 flow;
	struct rtable *table;

	memset(&flow, 0, sizeof(flow));
	/* flow.flowi4_oif; */
	/* flow.flowi4_iif; */
	/* flow.flowi4_mark = mark; */
	flow.flowi4_tos = RT_TOS(hdr->tos);
	flow.flowi4_scope = RT_SCOPE_UNIVERSE;
	flow.flowi4_proto = hdr->protocol;
	flow.flowi4_flags = 0;
	/* Only used by XFRM ATM (kernel/Documentation/networking/secid.txt). */
	/* flow.flowi4_secid; */
	/* flow.saddr = hdr->saddr; */
	flow.daddr = hdr->daddr;

	table = __ip_route_output_key(&init_net, &flow);
	if (!table || IS_ERR(table)) {
		log_err("__ip_route_output_key() returned %ld. Cannot route packet.",
				(long) table);
		return NULL;
	}

	return &table->dst;
}

/**
 * Returns a hack-free version of the 'Traffic class' field from the "hdr" IPv6
 * header.
 */
static __u8 get_traffic_class(struct ipv6hdr *hdr)
{
	__u8 upper_bits = hdr->priority;
	__u8 lower_bits = hdr->flow_lbl[0] >> 4;
	return (upper_bits << 4) | lower_bits;
}

/**
 * Returns a big endian (but otherwise hack-free) version of the 'Flow label'
 * field from the "hdr" IPv6 header.
 */
static __be32 get_flow_label(struct ipv6hdr *hdr)
{
	return (*(__be32 *) hdr) & IPV6_FLOWLABEL_MASK;
}

struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip)
{
	struct flowi6 flow;
	struct dst_entry *dst;

	memset(&flow, 0, sizeof(flow));
	/* flow->flowi6_oif; */
	/* flow->flowi6_iif; */
	/* flow.flowi6_mark = mark; */
	flow.flowi6_tos = get_traffic_class(hdr_ip);
	flow.flowi6_scope = RT_SCOPE_UNIVERSE;
	flow.flowi6_proto = hdr_ip->nexthdr;
	flow.flowi6_flags = 0;
	/* flow->flowi6_secid; */
	/* flow.saddr = hdr_ip->saddr; */
	flow.daddr = hdr_ip->daddr;
	flow.flowlabel = get_flow_label(hdr_ip);

	dst = ip6_route_output(&init_net, NULL, &flow);
	if (!dst) {
		log_err("ip6_route_output() returned NULL. Cannot route packet.");
		return NULL;
	}
	if (dst->error) {
		log_err("ip6_route_output() returned error %d. Cannot route packet.",
				-dst->error);
		return NULL;
	}

	return dst;
}

