#include "nat64/comm/nat64.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/fragment_db.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"
#include "nat64/mod/config.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/translate_packet.h"
#include "nat64/mod/core.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION(MODULE_NAME " (RFC 6146)");
MODULE_ALIAS("nat64");

static char *pool6[5];
static int pool6_size;
module_param_array(pool6, charp, &pool6_size, 0);
MODULE_PARM_DESC(pool6, "The IPv6 pool's prefixes.");
static char *pool4[5];
static int pool4_size;
module_param_array(pool4, charp, &pool4_size, 0);
MODULE_PARM_DESC(pool4, "The IPv4 pool's addresses.");


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
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = PF_INET6,
		.priority = NF_PRI_NAT64,
	},
	{
		.hook = hook_ipv4,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = PF_INET,
		.priority = NF_PRI_NAT64,
	},
	{
		.hook = hook_ipv6,
		.hooknum = NF_INET_LOCAL_OUT,
		.pf = PF_INET6,
		.priority = NF_PRI_NAT64,
	},
	{
		.hook = hook_ipv4,
		.hooknum = NF_INET_LOCAL_OUT,
		.pf = PF_INET,
		.priority = NF_PRI_NAT64,
	}
};

int __init nat64_init(void)
{
	int error;

	log_debug("%s", banner);
	log_debug("Inserting the module...");

	/* Init Jool's submodules. */
	error = pktmod_init();
	if (error)
		goto pktmod_failure;
	error = config_init();
	if (error)
		goto config_failure;
	error = fragdb_init();
	if (error)
		goto fragdb_failure;
	error = pool6_init(pool6, pool6_size);
	if (error)
		goto pool6_failure;
	error = pool4_init(pool4, pool4_size);
	if (error)
		goto pool4_failure;
	error = bib_init();
	if (error)
		goto bib_failure;
	error = session_init();
	if (error)
		goto session_failure;
	error = filtering_init();
	if (error)
		goto filtering_failure;
	error = translate_packet_init();
	if (error)
		goto translate_packet_failure;

	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info(MODULE_NAME " module inserted.");
	return error;

nf_register_hooks_failure:
	translate_packet_destroy();

translate_packet_failure:
	filtering_destroy();

filtering_failure:
	session_destroy();

session_failure:
	bib_destroy();

bib_failure:
	pool4_destroy();

pool4_failure:
	pool6_destroy();

pool6_failure:
	fragdb_destroy();

fragdb_failure:
	config_destroy();

config_failure:
	pktmod_destroy();

pktmod_failure:
	return error;
}

void __exit nat64_exit(void)
{
	/* Release the hook. */
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	/* Deinitialize the submodules. */
	translate_packet_destroy();
	filtering_destroy();
	session_destroy();
	bib_destroy();
	pool4_destroy();
	pool6_destroy();
	fragdb_destroy();
	config_destroy();
	pktmod_destroy();

	log_info(MODULE_NAME " module removed.");
}

module_init(nat64_init);
module_exit(nat64_exit);
