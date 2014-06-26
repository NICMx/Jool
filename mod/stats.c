#include "nat64/mod/stats.h"
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
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

void inc_stats_ipv6(struct sk_buff *skb, int field)
{
	struct inet6_dev *idev;

	if (is_error(inc_stats_validate(skb)))
		return;
	idev = in6_dev_get(skb->dev);
	if (!idev)
		return;

	IP6_INC_STATS_BH(dev_net(skb->dev), idev, field);

	in6_dev_put(idev);
}

void inc_stats_ipv4(struct sk_buff *skb, int field)
{
	if (is_error(inc_stats_validate(skb)))
		return;
	IP_INC_STATS_BH(dev_net(skb->dev), field);
}

void inc_stats(struct sk_buff *skb, int field)
{
	switch (ntohs(skb->protocol)) {
	case ETH_P_IPV6:
		inc_stats_ipv6(skb, field);
		break;
	case ETH_P_IP:
		inc_stats_ipv4(skb, field);
		break;
	}
}
