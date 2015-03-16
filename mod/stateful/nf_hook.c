#include "nat64/common/nat64.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/nl_handler.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/pkt_queue.h"
#include "nat64/mod/stateful/bib_db.h"
#include "nat64/mod/stateful/session_db.h"
#include "nat64/mod/stateful/fragment_db.h"
#ifdef BENCHMARK
#include "nat64/mod/common/log_time.h"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION(MODULE_NAME " (RFC 6146)");

static char *pool6[5];
static int pool6_size;
module_param_array(pool6, charp, &pool6_size, 0);
MODULE_PARM_DESC(pool6, "The IPv6 pool's prefixes.");
static char *pool4[5];
static int pool4_size;
module_param_array(pool4, charp, &pool4_size, 0);
MODULE_PARM_DESC(pool4, "The IPv4 pool's addresses.");
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

	log_debug("%s", banner);
	log_debug("Inserting the module...");

	nf_defrag_ipv6_enable();
	nf_defrag_ipv4_enable();

	/* Init Jool's submodules. */
	error = config_init(disabled);
	if (error)
		goto config_failure;
	error = nlhandler_init();
	if (error)
		goto nlhandler_failure;
	error = pool6_init(pool6, pool6_size);
	if (error)
		goto pool6_failure;
	error = pool4_init(pool4, pool4_size);
	if (error)
		goto pool4_failure;
	error = pktqueue_init();
	if (error)
		goto pktqueue_failure;
	error = bibdb_init();
	if (error)
		goto bib_failure;
	error = sessiondb_init();
	if (error)
		goto session_failure;
	error = fragdb_init();
	if (error)
		goto fragdb_failure;
#ifdef BENCHMARK
	error = logtime_init();
	if (error)
		goto log_time_failure;
#endif

	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info(MODULE_NAME " module inserted.");
	return error;

nf_register_hooks_failure:
#ifdef BENCHMARK
	logtime_destroy();

log_time_failure:
#endif
	fragdb_destroy();

fragdb_failure:
	sessiondb_destroy();

session_failure:
	bibdb_destroy();

bib_failure:
	pktqueue_destroy();

pktqueue_failure:
	pool4_destroy();

pool4_failure:
	pool6_destroy();

pool6_failure:
	nlhandler_destroy();

nlhandler_failure:
	config_destroy();

config_failure:
	return error;
}

static void __exit nat64_exit(void)
{
	/* Release the hook. */
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	/* Deinitialize the submodules. */
#ifdef BENCHMARK
	logtime_destroy();
#endif
	fragdb_destroy();
	sessiondb_destroy();
	bibdb_destroy();
	pktqueue_destroy();
	pool4_destroy();
	pool6_destroy();
	nlhandler_destroy();
	config_destroy();

	log_info(MODULE_NAME " module removed.");
}

module_init(nat64_init);
module_exit(nat64_exit);
