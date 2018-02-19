/*
 * Based on snull.c; the code comes from the book "Linux Device Drivers" by
 * Alessandro Rubini and Jonathan Corbet, published by O'Reilly & Associates.
 * No warranty is attached; we cannot take responsibility for errors or fitness
 * for use.
 */

#include "xlator.h"

#include "atomic-config.h"
#include "module-stats.h"
#include "wkmalloc.h"
#include "siit/eam.h"
#include "nat64/fragment_db.h"
#include "nat64/joold.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

/**
 * Private data each device will store.
 */
struct jool_netdev_priv {
	/**
	 * This instance is meat to be shallow-cloned for every translation.
	 *
	 * The reason why we need to clone it is because of Atomic
	 * Configuration. AC might change the device's xlator at any point.
	 * But this change should only affect new translations; ongoing
	 * translations should still keep the old config or they might bork
	 * things (eg. if they queried the old pool4 database, then they
	 * query the new database later).
	 *
	 * This is also sort of the reason why the xlator has to be allocated
	 * separately and managed via RCU. Every device must keep its
	 * netdev_priv until it dies, but the translator might change.
	 */
	struct xlator __rcu *jool;

	struct net_device_stats stats;

	/* TODO remember to lock. */
	/* TODO if @jool is all this needs to protect, this should be a mutex. */
	spinlock_t lock;
};

static struct jool_netdev_priv *get_priv(struct net_device *dev)
{
	return netdev_priv(dev);
}

static int find_device(char *name, struct net_device **result)
{
	struct net *ns;
	struct net_device *dev;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	dev = dev_get_by_name(ns, name);
	put_net(ns);
	if (!dev) {
		log_err("Device '%s' was not found in this namespace.", name);
		return -ESRCH;
	}

	*result = dev;
	return 0;
}

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

static void clone_xlator(struct net_device *dev, struct xlator *jool)
{
	rcu_read_lock_bh();
	memcpy(jool, rcu_dereference_bh(get_priv(dev)->jool), sizeof(*jool));
	xlator_get(jool);
	rcu_read_unlock_bh();
}

/*
 * Called by the kernel whenever it wants to send a packet via Jool's device.
 */
static int jool_netdev_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct xlator jool;

	// Save the timestamp TODO what for?
	dev->trans_start = jiffies;

	log_debug("===============================================");
	log_info("Received a packet from the kernel. Translating...");

	clone_xlator(dev, &jool);

	/*
	 * TODO if NETDEV_TX_BUSY doesn't do anything aside from stat tracking,
	 * maybe we're meat to return that on error.
	 */

	if (!pskb_may_pull(skb, ETH_HLEN)) {
		log_info("Packet is too short to even contain an Ethernet header.");
		/* There's not enough info to send an ICMP error. */
		jstat_inc(jool.stats, JOOL_MIB_TRUNCATED);
		kfree_skb(skb);
		goto end;
	}

	/* Don't need the ethernet header for anything. */
	skb_pull(skb, ETH_HLEN);

	switch (ntohs(skb->protocol)) {
	case ETH_P_IPV6:
		log_info("skb->proto says IPv6.");
		core_6to4(&jool, skb);
		break;
	case ETH_P_IP:
		log_info("skb->proto says IPv4.");
		core_4to6(&jool, skb);
		break;
	default:
		log_info("Packet is not IPv4 nor IPv6; don't know what to do.");
		/* ICMP errors not available due to unknown protocol. */
		jstat_inc(jool.stats, JOOL_MIB_UNKNOWN_L3);
		kfree_skb(skb);
	}
	/* Fall through */

end:
	xlator_put(&jool);
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

	/* At this point, this_cpu_read(*dev->pcpu_refcnt) = 0. I dunno why. */

	jool = wkmalloc(struct xlator, GFP_KERNEL);
	if (!jool)
		goto xlator_fail;
	RCU_INIT_POINTER(get_priv(dev)->jool, jool);

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

	/* this_cpu_read(*dev->pcpu_refcnt) = 0 */

	error = register_netdev(dev);
	if (error) {
		log_err("register_netdev(%s) error: %i", dev->name, error);
		goto register_fail;
	}

	/* this_cpu_read(*dev->pcpu_refcnt) = 7 */

	if (result) {
		xlator_get(jool);
		memcpy(result, jool, sizeof(*jool));
	}

	log_info("'%s' device created and registered.", dev->name);
	dev_put(dev);
	/*
	 * this_cpu_read(*dev->pcpu_refcnt) = 6
	 * TODO this smells pretty fishy. Other kernel citizens do not seem to
	 * call dev_put(dev) after they register the device. Figure it out.
	 */
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
	wkfree(struct xlator, jool);
xlator_fail:
	free_netdev(dev);
	return error;
}

int xlator_rm(char *name)
{
	struct net_device *dev;
	struct xlator *jool;
	int error;

	error = find_device(name, &dev);
	if (error)
		return error;

	/* this_cpu_read(*dev->pcpu_refcnt) = 7 */
	unregister_netdev(dev);
	/* this_cpu_read(*dev->pcpu_refcnt) = 0 */

	/*
	 * It doesn't appear that unregister_netdev()'s contract prevents
	 * packets from being in transit after the call, but looking at its
	 * code, it does appear that it is intended to be the case.
	 * (unlist_netdevice() then synchronize_net(), and also lots of
	 * per-protocol cleanup later, then synchronize_net() again. I'm reading
	 * kernel 4.15.)
	 *
	 * So throw caution to the wind, I guess.
	 */

	jool = rcu_dereference_protected(get_priv(dev)->jool, true);
	xlator_put(jool);
	wkfree(struct xlator, jool);
	free_netdev(dev);
	return 0;
}

int xlator_replace(char *name, struct xlator *new)
{
	struct net_device *dev;
	struct jool_netdev_priv *priv;
	struct xlator *old;
	int error;

	error = find_device(name, &dev);
	if (error)
		return error;

	priv = get_priv(dev);
	spin_lock(&priv->lock);
	old = rcu_dereference_protected(priv->jool, spin_is_locked(&priv->lock));
	rcu_assign_pointer(priv->jool, new);
	spin_unlock(&priv->lock);

	dev_put(dev);

	synchronize_rcu_bh();

	xlator_put(old);
	wkfree(struct xlator, old);
	return 0;
}

/**
 * Call xlator_put() on the result when you're done.
 */
int xlator_find(char *name, struct xlator *result)
{
	struct net_device *dev;
	int error;

	error = find_device(name, &dev);
	if (error)
		return error;

	clone_xlator(dev, result);

	dev_put(dev);
	return 0;
}

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
