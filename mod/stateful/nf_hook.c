#include "nat64/mod/common/nf_hook.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include "nat64/common/constants.h"
#include "nat64/common/xlat.h"
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/log_time.h"
#include "nat64/mod/common/nf_wrapper.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/timer.h"
#include "nat64/mod/stateful/bib/port_allocator.h"
#include "nat64/mod/stateful/pool4/db.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateful NAT64 (RFC 6146)");
MODULE_VERSION(JOOL_VERSION_STR);

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

static bool no_instance;
module_param(no_instance, bool, 0);
MODULE_PARM_DESC(no_instance, "Prevent an instance to be added to the current namespace during the modprobe.");


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


static NF_CALLBACK(hook_ipv6, skb)
{
	return core_6to4(skb, skb->dev);
}

static NF_CALLBACK(hook_ipv4, skb)
{
	return core_4to6(skb, skb->dev);
}

static struct nf_hook_ops nfho[] = {
	{
		.hook = hook_ipv6,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP6_PRI_JOOL,
	},
	{
		.hook = hook_ipv4,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_JOOL,
	},
};

static int add_instance(void)
{
	struct xlator jool;
	int error;

	if (no_instance)
		return 0;

	error = xlator_add(&jool);
	if (error)
		return error;

	jool.global->cfg.enabled = !disabled;
	error = pool6_add_str(jool.pool6, pool6, pool6_len);
	if (error)
		goto end;
	error = pool4db_add_str(jool.nat64.pool4, pool4, pool4_len);
	/* Fall through. */

end:
	xlator_put(&jool);
	return error;
}

static int __init jool_init(void)
{
	int error;

	log_debug("%s", banner);
	log_debug("Inserting %s...", xlat_get_name());

	/* Init Jool's submodules. */
	error = bibentry_init();
	if (error)
		goto bibentry_fail;
	error = session_init();
	if (error)
		goto session_fail;
	error = fragdb_init();
	if (error)
		goto fragdb_fail;
	error = joold_init();
	if (error)
		goto joold_fail;
	error = palloc_init();
	if (error)
		goto palloc_fail;
	error = xlator_init();
	if (error)
		goto xlator_fail;
	error = nlcore_init();
	if (error)
		goto nlcore_fail;
	error = timer_init();
	if (error)
		goto timer_fail;
	error = logtime_init();
	if (error)
		goto logtime_fail;

	/* This needs to be last! (except for the hook registering.) */
	error = add_instance();
	if (error)
		goto instance_fail;

	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_fail;

	/* Yay */
	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return error;

nf_register_hooks_fail:
	xlator_rm();
instance_fail:
	logtime_destroy();
logtime_fail:
	timer_destroy();
timer_fail:
	nlcore_destroy();
nlcore_fail:
	xlator_destroy();
xlator_fail:
	palloc_destroy();
palloc_fail:
	joold_terminate();
joold_fail:
	fragdb_destroy();
fragdb_fail:
	session_destroy();
session_fail:
	bibentry_destroy();
bibentry_fail:
	return error;
}

static void __exit jool_exit(void)
{
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	logtime_destroy();
	timer_destroy();
	nlcore_destroy();
	xlator_destroy();
	palloc_destroy();
	joold_terminate();
	fragdb_destroy();
	session_destroy();
	bibentry_destroy();

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_init);
module_exit(jool_exit);
