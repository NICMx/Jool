#include "nat64/mod/common/nf_hook.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include "nat64/common/constants.h"
#include "nat64/common/xlat.h"
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/log_time.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/nl/nl_handler.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/joold.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateful NAT64 (RFC 6146)");

static char *pool6[5];
static int pool6_len;
module_param_array(pool6, charp, &pool6_len, 0);
MODULE_PARM_DESC(pool6, "The IPv6 pool's prefixes.");

static char *pool4[5];
static int pool4_len;
module_param_array(pool4, charp, &pool4_len, 0);
MODULE_PARM_DESC(pool4, "The IPv4 pool's addresses.");

static unsigned int pool4_size;
module_param(pool4_size, uint, 0);
MODULE_PARM_DESC(pool4_size, "Size of pool4 DB's hashtable.");

static bool disabled;
module_param(disabled, bool, 0);
MODULE_PARM_DESC(disabled, "Disable the translation at the beginning of the module insertion.");


static char *banner = "\n"
	"                                   ,----,                       \n"
	"         ,--.                    ,/   .`|                 ,--,  \n"
	"       ,--.'|   ,---,          ,`   .'**:               ,--.'|  \n"
	"   ,--,:  :*|  '  .'*\\       ;    ;*****/  ,---.     ,--,  |#:  \n"
	",`--.'`|  '*: /  ;****'.   .'___,/****,'  /     \\ ,---.'|  :#'  \n"
	"|   :**:  |*|:  :*******\\  |    :*****|  /    /#' ;   :#|  |#;  \n"
	":   |***\\ |*::  |***/\\***\\ ;    |.';**; .    '#/  |   |#: _'#|  \n"
	"|   :*'**'; ||  :**' ;.***:`----'  |**|'    /#;   :   :#|.'##|  \n"
	"'   '*;.****;|  |**;/  \\***\\   '   :**;|   :##\\   |   '#'##;#:  \n"
	"|   |*| \\***|'  :**| \\  \\*,'   |   |**';   |###``.\\   \\##.'.#|  \n"
	"'   :*|  ;*.'|  |**'  '--'     '   :**|'   ;######\\`---`:  |#'  \n"
	"|   |*'`--'  |  :**:           ;   |.' '   |##.\\##|     '  ;#|  \n"
	"'   :*|      |  |*,'           '---'   |   :##';##:     |  :#;  \n"
	";   |.'      `--''                      \\   \\####/      '  ,/   \n"
	"'---'                                    `---`--`       '--'    \n";


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

	log_debug("%s", banner);
	log_debug("Inserting %s...", xlat_get_name());

	/* Init Jool's submodules. */
	error = bibentry_init();
	if (error)
		goto bibentry_failure;
	error = session_init();
	if (error)
		goto session_failure;
	error = joolns_init();
	if (error)
		goto joolns_failure;
	error = nl_core_init();
	if (error)
		goto nl_core_failure;
	error = nlhandler_init();
	if (error)
		goto nlhandler_failure;
	error = joold_init();
	if (error)
		goto joold_failure;
	error = logtime_init();
	if (error)
		goto logtime_failure;

	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return error;

nf_register_hooks_failure:
	logtime_destroy();
logtime_failure:
	joold_destroy();
joold_failure:
	nlhandler_destroy();
nlhandler_failure:
	nl_core_destroy();
nl_core_failure:
	joolns_destroy();
joolns_failure:
	session_destroy();
session_failure:
	bibentry_destroy();
bibentry_failure:
	return error;
}

static void __exit jool_exit(void)
{
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	logtime_destroy();
	joold_destroy();
	nlhandler_destroy();
	nl_core_destroy();
	joolns_destroy();
	session_destroy();
	bibentry_destroy();

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_init);
module_exit(jool_exit);
