#include "nat64/mod/common/nf_hook.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/log_time.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/nl/nl_handler.h"
#include "nat64/mod/common/types.h"

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

static int sock_family = NETLINK_USERSOCK;
module_param(sock_family, int, 0);
MODULE_PARM_DESC(sock_family, "Family of the socket which will handle userspace requests.");

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

static int /* __init TODO uncomment */ jool_init(void)
{
	int error;

	log_debug("Inserting %s...", xlat_get_name());

	/* Init Jool's submodules. */
	error = logtime_init();
	if (error)
		goto log_time_failure;
	error = joolns_init();
	if (error)
		goto joolns_failure;
	error = nlhandler_init(sock_family);
	if (error)
		goto nlhandler_failure;

	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return 0;

nf_register_hooks_failure:
	nlhandler_destroy();
nlhandler_failure:
	joolns_destroy();
joolns_failure:
	logtime_destroy();
log_time_failure:
	return error;
}

static void /* __exit TODO uncomment*/ jool_exit(void)
{
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	nlhandler_destroy();
	joolns_destroy();
	logtime_destroy();

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_init);
module_exit(jool_exit);
