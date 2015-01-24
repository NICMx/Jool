#include "nat64/mod/common/config.h"
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/nl_handler.h"
#include "nat64/mod/common/types.h"
#ifdef BENCHMARK
#include "nat64/mod/common/log_time.h"
#endif
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/pool4.h"
#include "nat64/mod/stateless/pool6.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION(MODULE_NAME " (RFC 6145)");

static char *pool6;
module_param(pool6, charp, 0);
MODULE_PARM_DESC(pool6, "The IPv6 prefix.");
static char *pool4[5];
static int pool4_size;
module_param_array(pool4, charp, &pool4_size, 0);
MODULE_PARM_DESC(pool4, "The IPv4 pool's addresses.");


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define HOOK_ARG_TYPE const struct nf_hook_ops *
#else
#define HOOK_ARG_TYPE unsigned int
#endif

static unsigned int hook_ipv4(HOOK_ARG_TYPE hook, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return core_4to6(skb);
}

static unsigned int hook_ipv6(HOOK_ARG_TYPE hook, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return core_6to4(skb);
}

static struct nf_hook_ops nfho[] = {
	{
		.hook = hook_ipv6,
		.pf = PF_INET6,
		.hooknum = NF_INET_LOCAL_IN
	},
	{
		.hook = hook_ipv6,
		.pf = PF_INET6,
		.hooknum = NF_INET_FORWARD
	},
	{
		.hook = hook_ipv6,
		.pf = PF_INET6,
		.hooknum = NF_INET_LOCAL_OUT
	},
	{
		.hook = hook_ipv4,
		.pf = PF_INET,
		/*
		 * Because the IPv4 addresses belong to the interface, the kernel doesn't send the packets
		 * via the FORWARD path, even though the ultimate intent is to forward them.
		 * Receiving all packets in LOCAL IN would not be a problem, however, if it wasn't because
		 * the kernel defragments before it, so we have to capture packets even before.
		 */
		.hooknum = NF_INET_PRE_ROUTING
	},
	{
		.hook = hook_ipv4,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT
	}
};

static int __init nat64_init(void)
{
	int i, error;

	log_debug("Inserting " MODULE_NAME "...");

	if (pool4_size == 0) {
		log_err("Missing argument 'pool4' (modprobe jool-stateless pool4=<addrs>).");
		return -EINVAL;
	}

	/* Init Jool's submodules. */
	error = config_init();
	if (error)
		goto config_failure;
	error = eamt_init();
	if (error)
		goto eamt_failure;
#ifdef BENCHMARK
	error = logtime_init();
	if (error)
		goto log_time_failure;
#endif
	error = nlhandler_init();
	if (error)
		goto nlhandler_failure;
	error = pool6_init(pool6);
	if (error)
		goto pool6_failure;
	error = pool4_init(pool4, pool4_size);
	if (error)
		goto pool4_failure;

	/* Hook Jool to Netfilter. */
	for (i = 0; i < ARRAY_SIZE(nfho); i++) {
		nfho[i].owner = NULL;
		nfho[i].priority = NF_IP_PRI_NAT_SRC + 25;
	}

	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info(MODULE_NAME " module inserted.");
	return error;

nf_register_hooks_failure:
	pool4_destroy();

pool4_failure:
	pool6_destroy();

pool6_failure:
	nlhandler_destroy();

nlhandler_failure:
#ifdef BENCHMARK
	logtime_destroy();

log_time_failure:
#endif
	eamt_destroy();

eamt_failure:
	config_destroy();

config_failure:
	return error;
}

static void __exit nat64_exit(void)
{
	/* Release the hook. */
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	/* Deinitialize the submodules. */
	pool4_destroy();
	pool6_destroy();
	nlhandler_destroy();
#ifdef BENCHMARK
	logtime_destroy();
#endif
	eamt_destroy();
	config_destroy();

	log_info(MODULE_NAME " module removed.");
}

module_init(nat64_init);
module_exit(nat64_exit);
