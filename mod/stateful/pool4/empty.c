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
			if (ifa->ifa_address == addr->s_addr)
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

/**
 * Normally picks the first primary global address of @dst's interface.
 * If there's a primary global address that matches @daddr however, it takes
 * precedence.
 * If everything fails, attempts to use a host address.
 *
 * Notice that this code is mostly just a ripoff of inet_select_addr().
 */
static int __pick_addr(struct dst_entry *dst, struct route4_args *args,
		struct in_addr *result)
{
	struct in_device *in_dev;
	__be32 saddr = 0;

	in_dev = __in_dev_get_rcu(dst->dev);
	if (!in_dev) {
		log_debug("IPv4 route doesn't involve an IPv4 device.");
		return -EINVAL;
	}

	for_primary_ifa(in_dev) {
		if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
			continue;
		if (inet_ifa_match(args->daddr.s_addr, ifa)) {
			result->s_addr = ifa->ifa_local;
			return 0;
		}
		if (!saddr)
			saddr = ifa->ifa_local;
	} endfor_ifa(in_dev);

	if (saddr) {
		result->s_addr = saddr;
		return 0; /* This is the typical happy path. */
	}

	/*
	 * TODO This seems to exist because of hairpinning.
	 * If the destination is ourselves, set source as ourselves.
	 * But is it really necessary? I feel like the inet_ifa_match() above
	 * should have that covered. Please test.
	 *
	 * If this does not serve any purpose, consider using inet_select_addr()
	 * instead of having to maintain this function.
	 */
	if (contains_addr(args->ns, &args->daddr)) {
		*result = args->daddr;
		return 0;
	}

	log_debug("Couldn't find a good source address candidate.");
	return -ESRCH;
}

static int pick_addr(struct dst_entry *dst, struct route4_args *route_args,
		struct in_addr *result)
{
	int error;

	rcu_read_lock();
	error = __pick_addr(dst, route_args, result);
	rcu_read_unlock();

	return error;
}

int pool4empty_find(struct route4_args *route_args, struct pool4_range *range)
{
	struct dst_entry *dst;
	int error;

	dst = __route4(route_args, NULL);
	if (!dst)
		return -ENOMEM;

	/* This initialization shuts up old versions of gcc. */
	range->addr.s_addr = 0;
	error = pick_addr(dst, route_args, &range->addr);
	if (!error) {
		range->ports.min = DEFAULT_POOL4_MIN_PORT;
		range->ports.max = DEFAULT_POOL4_MAX_PORT;
	}

	/*
	 * The outgoing packet hasn't been allocated yet, so we don't have a
	 * placeholder for this. We will therefore have to regenerate it later.
	 * Life sucks :-).
	 *
	 * TODO (performance) if you can send the xlator in, we would have a
	 * placeholder.
	 */
	dst_release(dst);
	return error;
}
