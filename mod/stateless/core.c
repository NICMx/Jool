#include "nat64/mod/common/core.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/rfc6145/core.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


static unsigned int core_common(struct sk_buff *skb_in)
{
	struct sk_buff *skb_out;
	verdict result;

	result = translating_the_packet(NULL, skb_in, &skb_out);

	return (unsigned int) result;
}

unsigned int core_4to6(struct sk_buff *skb)
{
	struct iphdr *hdr = ip_hdr(skb);
	int error;

	log_debug("===============================================");
	log_debug("Catching IPv4 packet: %pI4->%pI4", &hdr->saddr, &hdr->daddr);

	if (WARN(skb_shared(skb), "The packet is shared!"))
		return NF_DROP;

	error = skb_init_cb_ipv4(skb);
	if (error)
		return NF_DROP;

	error = validate_icmp4_csum(skb);
	if (error) {
		inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
		skb_clear_cb(skb);
		return NF_DROP;
	}

	return core_common(skb);
}

unsigned int core_6to4(struct sk_buff *skb)
{
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	int error;

	log_debug("===============================================");
	log_debug("Catching IPv6 packet: %pI6c->%pI6c", &hdr->saddr, &hdr->daddr);

	if (WARN(skb_shared(skb), "The packet is shared!"))
		return NF_DROP;

	error = skb_init_cb_ipv6(skb);
	if (error)
		return NF_DROP;

	error = validate_icmp6_csum(skb);
	if (error) {
		inc_stats(skb, IPSTATS_MIB_INHDRERRORS);
		skb_clear_cb(skb);
		return NF_DROP;
	}

	return core_common(skb);
}
