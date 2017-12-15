/*
 * Based on snull.c; the code comes from the book "Linux Device Drivers" by
 * Alessandro Rubini and Jonathan Corbet, published by O'Reilly & Associates.
 * No warranty is attached; we cannot take responsibility for errors or fitness
 * for use.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>

#include "core.h"
#include "log.h"
#include "module-stats.h"
#include "xlat.h"
#include "xlator.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("IP/ICMP Translator (RFCs 7915 and 6146)");
MODULE_VERSION(JOOL_VERSION_STR);

/*
 * The interface/device; seen by executing `ip addr`.
 * There's only one device right now, but of course Jool will need to be able to
 * manage any number of them.
 */
struct net_device *jool_dev;

/**
 * Private data each device will store.
 */
struct jool_netdev_priv {
	/* TODO remember to lock. */
	struct xlator jool;
	struct net_device_stats stats;
	spinlock_t lock;
};

/**
 * AFAIK, executed when the user runs `ip link set <name> up`.
 */
static int jool_netdev_open(struct net_device *dev)
{
	netif_start_queue(dev);
	log_info("Opened packet queue.");
	return 0;
}

/**
 * AFAIK, executed when the user runs `ip link set <name> down`.
 */
static int jool_netdev_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	log_info("Stopped packet queue.");
	return 0;
}

/*
 * Called by the kernel whenever it wants to send a packet via Jool's device.
 */
static int jool_netdev_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct jool_netdev_priv *priv = netdev_priv(dev);
	struct xlation state;

	// Save the timestamp TODO what for?
	dev->trans_start = jiffies;

	log_info("Received a packet from the kernel. Translating...");

	if (!pskb_may_pull(skb, ETH_HLEN)) {
		log_info("Packet is too short to even contain an Ethernet header.");
		/* There's not enough info to send an ICMP error. */
		jstat_inc(priv->jool.stats, JOOL_MIB_TRUNCATED);
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	/* Don't need the ethernet header for anything. */
	skb_pull(skb, ETH_HLEN);

	xlation_init(&state, &priv->jool);

	switch (ntohs(skb->protocol)) {
	case ETH_P_IPV6:
		log_info("skb->proto says IPv6.");
		core_6to4(&state, skb);
		break;
	case ETH_P_IP:
		log_info("skb->proto says IPv4.");
		core_4to6(&state, skb);
		break;
	default:
		log_info("Packet is not IPv4 nor IPv6; don't know what to do.");
		/* ICMP errors not available due to unknown protocol. */
		jstat_inc(state.jool.stats, JOOL_MIB_UNKNOWN_L3);
		kfree_skb(skb);
	}

	xlation_put(&state);
	return NETDEV_TX_OK;
}

/**
 * Return statistics to the caller
 */
static struct net_device_stats *jool_netdev_get_stats(struct net_device *dev)
{
	struct jool_netdev_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

static const struct net_device_ops jool_netdev_ops = {
	.ndo_open       = jool_netdev_open,
	.ndo_stop       = jool_netdev_stop,
	.ndo_start_xmit = jool_netdev_start_xmit,
	/*
	 * TODO I removed this because I don't get most of the fields.
	 * Experiment a little and then come back.
	 *
	 * .ndo_set_config = jool_netdev_set_config,
	 */
	.ndo_get_stats  = jool_netdev_get_stats,
};

static void jool_netdev_init(struct net_device *dev)
{
	struct jool_netdev_priv *priv;
	unsigned int i;

	ether_setup(dev);
	dev->netdev_ops = &jool_netdev_ops;
	dev->flags |= IFF_NOARP;
	// dev->features |= NETIF_F_HW_CSUM;

	for (i = 0; i < ETH_ALEN; i++)
		dev->dev_addr[i] = 0x64;

	priv = netdev_priv(dev);
	memset(&priv->jool, 0, sizeof(priv->jool));
	memset(&priv->stats, 0, sizeof(priv->stats));
	spin_lock_init(&priv->lock);
}

int jool_netdev_init_module(void)
{
	struct jool_netdev_priv *priv;
	int error;

	log_info("Inserting %s...", xlat_get_name());

	jool_dev = alloc_netdev(sizeof(struct jool_netdev_priv), "jool%d",
			NET_NAME_UNKNOWN, jool_netdev_init);
	if (!jool_dev)
		return -ENOMEM;

	priv = netdev_priv(jool_dev);
	error = xlator_add(XLATOR_NAT64, &priv->jool);
	if (error) {
		free_netdev(jool_dev);
		return error;
	}

	error = register_netdev(jool_dev);
	if (error) {
		log_info("register_netdev(%s) error: %i", jool_dev->name,
				error);
		free_netdev(jool_dev);
		return error;
	}

	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return 0;
}

void jool_netdev_cleanup_module(void)
{
	struct jool_netdev_priv *priv = netdev_priv(jool_dev);

	unregister_netdev(jool_dev);
	xlator_put(&priv->jool);
	free_netdev(jool_dev);

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_netdev_init_module);
module_exit(jool_netdev_cleanup_module);
