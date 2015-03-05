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
#include "nat64/mod/stateless/rfc6791.h"

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
static char *blacklist[5];
static int blacklist_size;
module_param_array(blacklist, charp, &blacklist_size, 0);
MODULE_PARM_DESC(blacklist, "IPv4 addresses that will not be translated.");
static char *errorAddresses[5];
static int errorAddresses_size;
module_param_array(errorAddresses, charp, &errorAddresses_size, 0);
MODULE_PARM_DESC(errorAddresses, "The RFC6791 pool's addresses.");
static bool disabled;
module_param(disabled, bool, 0);
MODULE_PARM_DESC(disabled, "Disable the translation at the beginning of the module insertion.");


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
		.owner = NULL,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP6_PRI_JOOL,
	},
	{
		.hook = hook_ipv4,
		.owner = NULL,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_JOOL,
	},
};

static int __init nat64_init(void)
{
	int error;

	log_debug("Inserting " MODULE_NAME "...");

	/* Init Jool's submodules. */
	error = config_init(disabled);
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
	error = rfc6791_init(errorAddresses, errorAddresses_size);
	if (error)
		goto rfc6791_failure;

	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info(MODULE_NAME " module inserted.");
	return error;

nf_register_hooks_failure:
	rfc6791_destroy();

rfc6791_failure:
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
	rfc6791_destroy();
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
