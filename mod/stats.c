#include "nat64/mod/stats.h"
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include "nat64/mod/packet.h"
#include "nat64/mod/types.h"


static int inc_stats_validate(struct sk_buff *skb)
{
	if (!skb)
		return -EINVAL;
	if (unlikely(!skb->dev))
		return -EINVAL;
	if (unlikely(!dev_net(skb->dev)))
		return -EINVAL;

	return 0;
}

static void inc_stats_ipv6(struct sk_buff *skb, int field)
{
	struct inet6_dev *idev;

	if (is_error(inc_stats_validate(skb))) {
		/* Maybe we can fall back to increase the stat on the other skb's dev... */
		skb = skb_original_skb(skb);
		if (is_error(inc_stats_validate(skb)))
			return;
	}
	idev = in6_dev_get(skb->dev);
	if (!idev)
		return;

	IP6_INC_STATS_BH(dev_net(skb->dev), idev, field);

	in6_dev_put(idev);
}

static void inc_stats_ipv4(struct sk_buff *skb, int field)
{
	if (is_error(inc_stats_validate(skb))) {
		skb = skb_original_skb(skb);
		if (is_error(inc_stats_validate(skb)))
			return;
	}
	IP_INC_STATS_BH(dev_net(skb->dev), field);
}

static void inc_stats_full(struct sk_buff *skb, int field) {
	switch (ntohs(skb->protocol)) {
	case ETH_P_IPV6:
		do {
			inc_stats_ipv6(skb, field);
			skb = skb->next;
		} while (skb);
		break;
	case ETH_P_IP:
		do {
			inc_stats_ipv4(skb, field);
			skb = skb->next;
		} while (skb);
		break;
	}
}

static void inc_stats_simple(struct sk_buff *skb, int field) {
	switch (ntohs(skb->protocol)) {
	case ETH_P_IPV6:
		inc_stats_ipv6(skb, field);
		break;
	case ETH_P_IP:
		inc_stats_ipv4(skb, field);
		break;
	}
}

void inc_stats(struct sk_buff *skb, int field)
{
	if (unlikely(!skb))
		return;

	switch (field) {
	case IPSTATS_MIB_INNOROUTES:		/* InNoRoutes */
	case IPSTATS_MIB_INADDRERRORS:		/* InAddrErrors */
	case IPSTATS_MIB_INDISCARDS: 		/* InDiscards */
	case IPSTATS_MIB_OUTDISCARDS:		/* OutDiscards */
	case IPSTATS_MIB_OUTNOROUTES:		/* OutNoRoutes */
	case IPSTATS_MIB_FRAGCREATES:		/* FragCreates */
		inc_stats_full(skb, field);
		break;
	default:
		inc_stats_simple(skb, field);
		break;
	}
}
