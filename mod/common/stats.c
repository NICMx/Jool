#include "nat64/mod/common/stats.h"
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/types.h"


static int validate_skb(struct sk_buff *skb)
{
	if (unlikely(!skb))
		return -EINVAL;
	if (unlikely(!skb->dev))
		return -EINVAL;
	if (unlikely(!dev_net(skb->dev)))
		return -EINVAL;

	return 0;
}

static int validate_pkt(struct packet *pkt)
{
	return likely(pkt) ? validate_skb(pkt->skb) : -EINVAL;
}

static void inc_stats6(struct sk_buff *skb, int field)
{
	struct inet6_dev *idev = in6_dev_get(skb->dev);
	if (!idev)
		return;

	IP6_INC_STATS_BH(dev_net(skb->dev), idev, field);

	in6_dev_put(idev);
}

static void inc_stats4(struct sk_buff *skb, int field)
{
	IP_INC_STATS_BH(dev_net(skb->dev), field);
}

void inc_stats_skb6(struct sk_buff *skb, int field)
{
	if (!is_error(validate_skb(skb)))
		inc_stats6(skb, field);
}

void inc_stats_skb4(struct sk_buff *skb, int field)
{
	if (!is_error(validate_skb(skb)))
		inc_stats4(skb, field);
}

static void inc_stats_pkt6(struct packet *pkt, int field)
{
	if (is_error(validate_pkt(pkt))) {
		/* Maybe we can fall back to increase the stat on the other skb's dev... */
		pkt = pkt_original_pkt(pkt);
		if (is_error(validate_pkt(pkt)))
			return;
	}

	inc_stats6(pkt->skb, field);
}

static void inc_stats_pkt4(struct packet *pkt, int field)
{
	if (is_error(validate_pkt(pkt))) {
		pkt = pkt_original_pkt(pkt);
		if (is_error(validate_pkt(pkt)))
			return;
	}

	inc_stats4(pkt->skb, field);
}

void inc_stats(struct packet *pkt, int field)
{
	if (unlikely(!pkt || !pkt->skb))
		return;

	switch (ntohs(pkt->skb->protocol)) {
	case ETH_P_IPV6:
		inc_stats_pkt6(pkt, field);
		break;
	case ETH_P_IP:
		inc_stats_pkt4(pkt, field);
		break;
	}
}
