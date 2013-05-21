#include "nat64/comm/nat64.h"
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
/* MODULE_ALIAS("nat64"); TODO (Issue #39) uncomment when we fix the project's name. */

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


static unsigned int hook_ipv4(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return core_4to6(skb);
}

static unsigned int hook_ipv6(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return core_6to4(skb);
}

static void deinit(void)
{
	translate_packet_destroy();
	filtering_destroy();
	session_destroy();
	bib_destroy();
	pool4_destroy();
	pool6_destroy();
	config_destroy();
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
	}
};

int __init nat64_init(void)
{
	int error;

	log_debug("%s", banner);
	log_debug("Inserting the module...");

	error = config_init();
	if (error)
		goto failure;
	error = pool6_init(pool6, pool6_size);
	if (error)
		goto failure;
	error = pool4_init(pool4, pool4_size);
	if (error)
		goto failure;
	error = bib_init();
	if (error)
		goto failure;
	error = session_init(session_expired);
	if (error)
		goto failure;
	error = filtering_init();
	if (error)
		goto failure;
	error = translate_packet_init();
	if (error)
		goto failure;

	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto failure;

	log_debug("Ok, success.");
	return error;

failure:
	deinit();
	return error;
}

void __exit nat64_exit(void)
{
	deinit();
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));
	log_debug(MODULE_NAME " module removed.");
}

module_init(nat64_init);
module_exit(nat64_exit);
