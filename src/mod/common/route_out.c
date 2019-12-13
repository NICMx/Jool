#include "mod/common/route.h"

#include <net/ip6_route.h>
#include <net/route.h>
#include "mod/common/log.h"

struct dst_entry *route4(struct net *ns, struct flowi4 *flow)
{
	struct rtable *table;
	struct dst_entry *dst;

	/*
	 * I'm using neither ip_route_output_key() nor ip_route_output_flow()
	 * because they only add XFRM overhead.
	 */
	table = __ip_route_output_key(ns, flow);
	if (!table || IS_ERR(table)) {
		log_debug("__ip_route_output_key() returned %ld. Cannot route packet.",
				PTR_ERR(table));
		return NULL;
	}

	dst = &table->dst;
	if (dst->error) {
		log_debug("__ip_route_output_key() returned error %d. Cannot route packet.",
				dst->error);
		goto revert;
	}

	if (!dst->dev) {
		log_debug("I found a dst entry with no dev; I don't know what to do.");
		goto revert;
	}

	log_debug("Packet routed via device '%s'.", dst->dev->name);
	return dst;

revert:
	dst_release(dst);
	return NULL;
}

struct dst_entry *route6(struct net *ns, struct flowi6 *flow)
{
	struct dst_entry *dst;

	dst = ip6_route_output(ns, NULL, flow);
	if (!dst) {
		log_debug("ip6_route_output() returned NULL. Cannot route packet.");
		return NULL;
	}
	if (dst->error) {
		log_debug("ip6_route_output() returned error %d. Cannot route packet.",
				dst->error);
		dst_release(dst);
		return NULL;
	}

	log_debug("Packet routed via device '%s'.", dst->dev->name);
	return dst;
}
