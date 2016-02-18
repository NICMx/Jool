#include "util.h"

#include <linux/version.h>
#include <net/net_namespace.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include "types.h"

int ip6_local_out_wrapped(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_nr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = ip6_local_out(ns, NULL, skb);
	put_net(ns);
	return error;
#else
	return ip6_local_out(skb);
#endif
}

int ip_local_out_wrapped(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_nr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = ip_local_out(ns, NULL, skb);
	put_net(ns);
	return error;
#else
	return ip_local_out(skb);
#endif
}
