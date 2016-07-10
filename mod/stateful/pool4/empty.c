#include "nat64/mod/stateful/pool4/empty.h"
#include <linux/inetdevice.h>
#include <linux/in_route.h>
#include <linux/netdevice.h>
#include "nat64/common/constants.h"
#include "nat64/mod/common/ipv6_hdr_iterator.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/rfc6145/6to4.h"

static bool contains_addr(const struct in_addr *addr)
{
	struct net_device *dev;
	struct in_device *in_dev;

	for_each_netdev_rcu(joolns_get(), dev) {
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

bool pool4empty_contains(const struct ipv4_transport_addr *addr)
{
	bool found;

	if (addr->l4 < DEFAULT_POOL4_MIN_PORT)
		return false;
	/* I sure hope this gets compiled out :p */
	if (DEFAULT_POOL4_MAX_PORT < addr->l4)
		return false;

	rcu_read_lock();
	found = contains_addr(&addr->l3);
	rcu_read_unlock();

	return found;
}

static struct dst_entry *____route4(struct packet *in, struct in_addr *daddr)
{
	struct ipv6hdr *hdr = pkt_ip6_hdr(in);
	__u8 tos = ttp64_xlat_tos(hdr);
	__u8 proto = ttp64_xlat_proto(hdr);

	return __route4(daddr->s_addr, tos, proto, in->skb->mark, NULL);
}

/**
 * Normally picks the first primary global address of @dst's interface.
 * If there's a primary global address that matches @daddr however, it takes
 * precedence.
 * If everything fails, attempts to use a host address.
 */
static int __pick_addr(struct dst_entry *dst, struct in_addr *daddr,
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
		if (inet_ifa_match(daddr->s_addr, ifa)) {
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

	if (contains_addr(daddr)) {
		*result = *daddr;
		return 0;
	}

	log_debug("Couldn't find a good source address candidate.");
	return -ESRCH;
}

static int pick_addr(struct dst_entry *dst, struct in_addr *daddr,
		struct in_addr *result)
{
	int error;

	rcu_read_lock();
	error = __pick_addr(dst, daddr, result);
	rcu_read_unlock();

	return error;
}

static int foreach_port(struct in_addr *addr,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	const unsigned int MIN = DEFAULT_POOL4_MIN_PORT;
	const unsigned int MAX = DEFAULT_POOL4_MAX_PORT;
	unsigned int i;
	struct ipv4_transport_addr tmp;
	int error;

	offset = MIN + (offset % (MAX - MIN + 1));
	tmp.l3 = *addr;

	for (i = offset; i <= MAX; i++) {
		tmp.l4 = i;
		error = cb(&tmp, arg);
		if (error)
			return error;
	}

	for (i = DEFAULT_POOL4_MIN_PORT; i < offset; i++) {
		tmp.l4 = i;
		error = cb(&tmp, arg);
		if (error)
			return error;
	}

	return 0;
}

int pool4empty_foreach_taddr4(struct packet *in, struct in_addr *daddr,
		int (*cb)(struct ipv4_transport_addr *, void *), void *arg,
		unsigned int offset)
{
	struct in_addr saddr;
	struct dst_entry *dst;
	int error;

	dst = ____route4(in, daddr);
	if (!dst)
		return -EINVAL;

	/* This initialization shuts up old versions of gcc. */
	saddr.s_addr = 0;
	error = pick_addr(dst, daddr, &saddr);
	if (error)
		goto end;

	error = foreach_port(&saddr, cb, arg, offset);
	/* Fall through. */

end:
	/*
	 * The outgoing packet hasn't been allocated yet, so we don't have
	 * a placeholder for this. We will therefore have to regenerate it
	 * later.
	 * Life sucks :-).
	 */
	dst_release(dst);
	return error;
}
