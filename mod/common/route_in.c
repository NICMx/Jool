#include "nat64/mod/common/route.h"

#include <linux/ip.h>
#include <net/route.h>
#include "nat64/mod/common/stats.h"

int route4_input(struct packet *pkt)
{
	struct iphdr *hdr;
	struct sk_buff *skb;
	int error;

	if (unlikely(!pkt)) {
		log_err("pkt can't be empty");
		return -EINVAL;
	}

	skb = pkt->skb;
	if (unlikely(!skb) || !skb->dev) {
		log_err("pkt->skb can't be empty");
		return -EINVAL;
	}

	hdr = ip_hdr(skb);
	error = ip_route_input(skb, hdr->daddr, hdr->saddr, hdr->tos, skb->dev);
	if (error) {
		log_debug("ip_route_input failed: %d", error);
		inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
	}

	return error;
}
