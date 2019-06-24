#include "mod/common/route.h"

#include "mod/common/log.h"

int route4_input(struct sk_buff *skb)
{
	struct iphdr *hdr;
	int error;

	if (!skb->dev) {
		log_err("skb lacks an incoming device.");
		return -EINVAL;
	}

	hdr = ip_hdr(skb);
	error = ip_route_input(skb, hdr->daddr, hdr->saddr, hdr->tos, skb->dev);
	if (error)
		log_debug("ip_route_input failed: %d", error);

	return error;
}
