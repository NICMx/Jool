/*
 * Based on snull.c; the code comes from the book "Linux Device Drivers" by
 * Alessandro Rubini and Jonathan Corbet, published by O'Reilly & Associates.
 * No warranty is attached; we cannot take responsibility for errors or fitness
 * for use.
 */

#include "xlator.h"

#include "atomic-config.h"
#include "module-stats.h"
#include "siit/eam.h"
#include "nat64/joold.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

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
	memset(dev->dev_addr, 0x64, ETH_ALEN);
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

	// Save the timestamp TODO what for?
	dev->trans_start = jiffies;

	log_debug("===============================================");
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

	switch (ntohs(skb->protocol)) {
	case ETH_P_IPV6:
		log_info("skb->proto says IPv6.");
		core_6to4(&priv->jool, skb);
		break;
	case ETH_P_IP:
		log_info("skb->proto says IPv4.");
		core_4to6(&priv->jool, skb);
		break;
	default:
		log_info("Packet is not IPv4 nor IPv6; don't know what to do.");
		/* ICMP errors not available due to unknown protocol. */
		jstat_inc(priv->jool.stats, JOOL_MIB_UNKNOWN_L3);
		kfree_skb(skb);
	}

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

	ether_setup(dev);
	dev->netdev_ops = &jool_netdev_ops;
	dev->flags |= IFF_NOARP;
	dev->features |= NETIF_F_HW_CSUM;

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(*priv));
	spin_lock_init(&priv->lock);
}

int xlator_add(struct xlator *result, xlator_type type, char *name)
{
	struct net_device *dev;
	struct xlator *jool;
	int error = -ENOMEM;

	log_info("Creating the '%s' device...", name);

	dev = alloc_netdev(sizeof(struct jool_netdev_priv), name,
			NET_NAME_UNKNOWN, jool_netdev_init);
	if (!dev)
		return error;

	jool = &((struct jool_netdev_priv *)netdev_priv(dev))->jool;

	jool->stats = jstat_alloc();
	if (!jool->stats)
		goto stats_fail;
	jool->global = config_init(type);
	if (!jool->global)
		goto config_fail;
	/*
	jool->newcfg = cfgcandidate_create();
	if (!jool->newcfg)
		goto newcfg_fail;
	*/
	jool->eamt = eamt_init();
	if (!jool->eamt)
		goto eamt_fail;
	jool->pool4 = pool4db_init();
	if (!jool->pool4)
		goto pool4_fail;
	jool->bib = bib_create();
	if (!jool->bib)
		goto bib_fail;
	jool->joold = joold_create();
	if (!jool->joold)
		goto joold_fail;

	error = register_netdev(dev);
	if (error) {
		log_err("register_netdev(%s) error: %i", dev->name, error);
		goto register_fail;
	}

	if (result) {
		xlator_get(jool);
		memcpy(result, jool, sizeof(*jool));
	}

	log_info("'%s' device created and registered.", dev->name);
	return 0;

register_fail:
	joold_put(jool->joold);
joold_fail:
	bib_put(jool->bib);
bib_fail:
	pool4db_put(jool->pool4);
pool4_fail:
	eamt_put(jool->eamt);
eamt_fail:
	/* TODO
	cfgcandidate_put(jool->newcfg);
newcfg_fail:
	*/
	config_put(jool->global);
config_fail:
	jstat_put(jool->stats);
stats_fail:
	free_netdev(dev);
	return error;
}

/* TODO delete */
#include <linux/atomic.h>

int xlator_rm(char *name)
{
	struct net *ns;
	struct net_device *dev;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	dev = dev_get_by_name(ns, name);
	if (!dev) {
		log_err("Device '%s' was not found in this namespace.", name);
		put_net(ns);
		return -ESRCH;
	}

	unregister_netdevice(dev);
	log_debug("CHECK 1 = %u", atomic_read(&dev->dev.kobj.kref.refcount));
	free_netdev(dev);
	put_net(ns);
	return 0;
}

//int xlator_replace(struct xlator *jool)
//{
//	return -EINVAL;
//	/* TODO fix thins when you have the userspace app figured out.
//	struct list_head *list;
//	struct jool_instance *old;
//	struct jool_instance *new;
//
//	new = wkmalloc(struct jool_instance, GFP_KERNEL);
//	if (!new)
//		return -ENOMEM;
//	memcpy(&new->jool, jool, sizeof(*jool));
//	xlator_get(&new->jool);
//
//	mutex_lock(&lock);
//
//	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
//	list_for_each_entry_rcu(old, list, list_hook) {
//		if (old->jool.ns == new->jool.ns) {
//			/ The comments at exit_net() also apply here. /
//#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
//			new->nf_ops = old->nf_ops;
//#endif
//			list_replace_rcu(&old->list_hook, &new->list_hook);
//			mutex_unlock(&lock);
//
//			synchronize_rcu_bh();
//
//#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
//			old->nf_ops = NULL;
//#endif
//			destroy_jool_instance(old);
//			return 0;
//		}
//	}
//
//	mutex_unlock(&lock);
//	return -ESRCH;
//	*/
//}

void xlator_get(struct xlator *jool)
{
	jstat_get(jool->stats);
	config_get(jool->global);
	/* TODO
	cfgcandidate_get(jool->newcfg);
	*/
	eamt_get(jool->eamt);
	pool4db_get(jool->pool4);
	bib_get(jool->bib);
	joold_get(jool->joold);
}

/*
 * I am kref_put()ting and there's no lock.
 * This can be dangerous: http://lwn.net/Articles/93617/
 *
 * I believe this is safe because this module behaves as as a "home" for all
 * these objects. While this module is dropping its reference, the refcounter
 * is guaranteed to be at least 1. Nobody can get a new reference while or after
 * this happens. Therefore nobody can sneak in a kref_get during the final put.
 */
void xlator_put(struct xlator *jool)
{
	jstat_put(jool->stats);
	config_put(jool->global);
	/* TODO
	cfgcandidate_put(jool->newcfg);
	*/
	eamt_put(jool->eamt);
	pool4db_put(jool->pool4);
	bib_put(jool->bib);
	joold_put(jool->joold);
}

int xlator_foreach(xlator_foreach_cb cb, void *args)
{
	/* TODO fix when you merge #257. */
	return 0;
}

//void xlator_copy_config(struct xlator *jool, struct full_config *copy)
//{
//	config_copy(&jool->global->cfg, &copy->global);
//	bib_config_copy(jool->nat64.bib, &copy->bib);
//	joold_config_copy(jool->nat64.joold, &copy->joold);
//	copy->type = jool->type;
//}
