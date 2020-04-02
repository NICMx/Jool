#include "empty.h"

#include <linux/inetdevice.h>
#include <linux/in_route.h>
#include <linux/netdevice.h>
#include "common/constants.h"
#include "mod/common/ipv6_hdr_iterator.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"

static bool contains_addr(struct net *ns, const struct in_addr *addr)
{
	struct net_device *dev;
	struct in_device *in_dev;
#if LINUX_VERSION_AT_LEAST(5, 3, 0, 9999, 0)
	struct in_ifaddr *ifa;
#endif

	for_each_netdev_rcu(ns, dev) {
		in_dev = __in_dev_get_rcu(dev);
		if (!in_dev)
			continue;

#if LINUX_VERSION_AT_LEAST(5, 3, 0, 9999, 0)
		in_dev_for_each_ifa_rcu(ifa, in_dev) {
			if (ifa->ifa_flags & IFA_F_SECONDARY)
				continue;
			if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
				continue;
			if (ifa->ifa_local == addr->s_addr)
				return true;
		}
#else
		for_primary_ifa(in_dev) {
			if (ifa->ifa_scope != RT_SCOPE_UNIVERSE)
				continue;
			if (ifa->ifa_local == addr->s_addr)
				return true;
		} endfor_ifa(in_dev);
#endif
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
 * Initializes @range with the address candidates that could source a packet
 * routed with @route_args.
 */
void pool4empty_find(struct ipv4_range *range)
{
	range->prefix.addr.s_addr = 0;
	range->prefix.len = 0;
	range->ports.min = DEFAULT_POOL4_MIN_PORT;
	range->ports.max = DEFAULT_POOL4_MAX_PORT;
}
