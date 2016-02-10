#include "nat64/mod/common/nf_hook.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/log_time.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateless IP/ICMP Translation (RFC 6145)");

static char *pool6;
module_param(pool6, charp, 0);
MODULE_PARM_DESC(pool6, "The IPv6 prefix.");
static char *blacklist[5];
static int blacklist_size;
module_param_array(blacklist, charp, &blacklist_size, 0);
MODULE_PARM_DESC(blacklist, "IPv4 addresses that will not be translated.");
static char *pool6791[5];
static int pool6791_size;
module_param_array(pool6791, charp, &pool6791_size, 0);
MODULE_PARM_DESC(pool6791, "The RFC6791 pool's addresses.");
static bool disabled;
module_param(disabled, bool, 0);
MODULE_PARM_DESC(disabled, "Disable the translation at the beginning of the module insertion.");


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define HOOK_ARG_TYPE const struct nf_hook_ops *
#else
#define HOOK_ARG_TYPE unsigned int
#endif

static unsigned int hook_ipv4(HOOK_ARG_TYPE hook, struct sk_buff *skb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
		const struct nf_hook_state *state)
#else
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#endif
{
	return core_4to6(skb, skb->dev);
}

static unsigned int hook_ipv6(HOOK_ARG_TYPE hook, struct sk_buff *skb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
		const struct nf_hook_state *state)
#else
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
#endif
{
	return core_6to4(skb, skb->dev);
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

static int __init jool_init(void)
{
	int error;

	log_debug("Inserting %s...", xlat_get_name());

	/* Init Jool's submodules. */
	error = xlator_init();
	if (error)
		goto xlator_failure;
	error = logtime_init();
	if (error)
		goto log_time_failure;
	error = nlcore_init();
	if (error)
		goto nlcore_failure;

	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return 0;

nf_register_hooks_failure:
	nlcore_destroy();
nlcore_failure:
	logtime_destroy();
log_time_failure:
	xlator_destroy();
xlator_failure:
	return error;
}

static void __exit jool_exit(void)
{
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	nlcore_destroy();
	logtime_destroy();
	xlator_destroy();

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_init);
module_exit(jool_exit);
