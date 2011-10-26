#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>

#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_protocol.h>
#include "nf_nat64_auxiliary_functions.h"

/*
 * BEGIN: Packet Auxiliary Functions
 */

/*
 * Function that retrieves a pointer to the Layer 4 header.
 */
inline void * ip_data(struct iphdr *ip4)
{
	return (char *)ip4 + ip4->ihl*4;
}

/*
 * Function that gets the Layer 4 header length.
 */
int nat64_get_l4hdrlength(u_int8_t l4protocol)
{
	switch(l4protocol) {
		case IPPROTO_TCP:
			return sizeof(struct tcphdr);
		case IPPROTO_UDP:
			return sizeof(struct udphdr);
		case IPPROTO_ICMP:
			return sizeof(struct icmphdr);
		case IPPROTO_ICMPV6:
			return sizeof(struct icmp6hdr);
	}
	return -1;
}

/*
 * Function to get the Layer 3 header length.
 */
int nat64_get_l3hdrlen(struct sk_buff *skb, u_int8_t l3protocol)
{
	switch (l3protocol) {
		case NFPROTO_IPV4:
			pr_debug("NAT64 get_l3hdrlen is IPV4");
			return ip_hdrlen(skb);
		case NFPROTO_IPV6:
			pr_debug("NAT64 get_l3hdrlen is IPV6");
			return (skb_network_offset(skb) + 
					sizeof(struct ipv6hdr));
		default:
			return -1;
	}
}

/*
 * BEGIN SUBSECTION: ECDYSIS FUNCTIONS
 */

void checksum_adjust(uint16_t *sum, uint16_t old, uint16_t new, bool udp)
{
	uint32_t s;

	if (udp && !*sum)
		return;

	s = *sum + old - new;
	*sum = (s & 0xffff) + (s >> 16);

	if (udp && !*sum)
		*sum = 0xffff;
}

void checksum_remove(uint16_t *sum, uint16_t *begin, 
				uint16_t *end, bool udp)
{
        while (begin < end)
                checksum_adjust(sum, *begin++, 0, udp);
}

void checksum_add(uint16_t *sum, uint16_t *begin, 
				uint16_t *end, bool udp)
{
        while (begin < end)
                checksum_adjust(sum, 0, *begin++, udp);
}

void checksum_change(uint16_t *sum, uint16_t *x, 
				uint16_t new, bool udp)
{
	checksum_adjust(sum, *x, new, udp);
	*x = new;
}

void adjust_checksum_ipv6_to_ipv4(uint16_t *sum, struct ipv6hdr *ip6, 
		struct iphdr *ip4, bool udp)
{
	WARN_ON_ONCE(udp && !*sum);

	checksum_remove(sum, (uint16_t *)&ip6->saddr,
			(uint16_t *)(&ip6->saddr + 2), udp);

	checksum_add(sum, (uint16_t *)&ip4->saddr,
			(uint16_t *)(&ip4->saddr + 2), udp);
}

/*
 * END SUBSECTION: ECDYSIS FUNCTIONS
 */

/*
 * END: Packet Auxiliary Functions
 */
