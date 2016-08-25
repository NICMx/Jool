#include "nat64/mod/stateful/pool4/empty.h"

#include <linux/inetdevice.h>
#include <linux/in_route.h>
#include <linux/netdevice.h>
#include "nat64/common/constants.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/xlator.h"

static bool contains_addr(struct net *ns, const struct in_addr *addr)
{
	struct net_device *dev;
	struct in_device *in_dev;

	for_each_netdev_rcu(ns, dev) {
		in_dev = __in_dev_get_rcu(dev);
		if (!in_dev)
			continue;

		for_primary_ifa(in_dev) {
			if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
				continue;
			if (ifa->ifa_local == addr->s_addr)
				return true;
		} endfor_ifa(in_dev);
	}

	return false;
}

bool pool4empty_contains(struct net *ns, const struct ipv4_transport_addr *addr)
{
	bool found;

	if (addr->l4 < DEFAULT_POOL4_MIN_PORT)
		return false;
	/* I sure hope this gets compiled out :p */
	if (DEFAULT_POOL4_MAX_PORT < addr->l4)
		return false;

	rcu_read_lock();
	found = contains_addr(ns, &addr->l3);
	rcu_read_unlock();

	return found;
}

int pool4empty_find(struct route4_args *route_args, struct pool4_range *range)
{
	struct dst_entry *dst;

	dst = __route4(route_args, NULL);
	if (!dst)
		return -ENOMEM;

	/*
	 * For some strange reason I used to have a near complete ripoff of
	 * inet_select_addr() here. It kind of looks like the reason was that
	 * it had some special code that (seemingly) handled hairpinning but,
	 * after testing inet_select_addr(), it doesn't appear to make any
	 * difference.
	 * Consider trying the old code if this somehow fails. The last commit
	 * that had it was 00bb35f5ea2a6e23a8530f2e3e033d1afd964708.
	 */
	range->addr.s_addr = inet_select_addr(dst->dev,
			route_args->daddr.s_addr,
			RT_SCOPE_UNIVERSE);
	if (range->addr.s_addr) {
		range->ports.min = DEFAULT_POOL4_MIN_PORT;
		range->ports.max = DEFAULT_POOL4_MAX_PORT;
	} else {
		log_debug("Couldn't find a good source address candidate.");
	}

	/*
	 * The outgoing packet hasn't been allocated yet, so we don't have a
	 * placeholder for this. We will therefore have to regenerate it later.
	 * Life sucks :-)
	 *
	 * TODO (performance) if you can send the xlator in, we would have a
	 * placeholder.
	 */
	dst_release(dst);
	return range->addr.s_addr ? 0 : -ESRCH;
}
