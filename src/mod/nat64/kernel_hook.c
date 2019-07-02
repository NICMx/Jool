#include "mod/common/kernel_hook.h"

#include <linux/module.h>

#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/wkmalloc.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/nl_handler.h"
#include "mod/nat64/joold.h"
#include "mod/nat64/timer.h"
#include "mod/nat64/pool4/db.h"
#include "mod/nat64/pool4/rfc6056.h"
#include "mod/nat64/bib/db.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateful NAT64 (RFC 6146)");
MODULE_VERSION(JOOL_VERSION_STR);

/* Implementation function required by xlat.h */
xlator_type xlat_type(void)
{
	return XT_NAT64;
}

/* Implementation function required by xlat.h */
char const *xlat_get_name(void)
{
	return "NAT64 Jool";
}

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
static bool iptables_error;


/**
 * These are the objects we use to register the Netfilter hooks.
 */
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

/**
 * These are the objects we use to register the iptables targets.
 */
static struct xt_target targets[] = {
	{
		.name       = IPTABLES_NAT64_MODULE_NAME,
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = target_ipv6,
		.checkentry = target_checkentry,
		.targetsize = XT_ALIGN(sizeof(struct target_info)),
		.me         = THIS_MODULE,
	}, {
		.name       = IPTABLES_NAT64_MODULE_NAME,
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = target_ipv4,
		.checkentry = target_checkentry,
		.targetsize = XT_ALIGN(sizeof(struct target_info)),
		.me         = THIS_MODULE,
	},
};

void init_nf_hook_op6(struct nf_hook_ops *ops)
{
	memcpy(ops, &nfho[0], sizeof(nfho[0]));
}

void init_nf_hook_op4(struct nf_hook_ops *ops)
{
	memcpy(ops, &nfho[1], sizeof(nfho[1]));
}

static int __init jool_init(void)
{
	int error;

	log_debug("%s", banner);
	log_debug("Inserting %s...", xlat_get_name());

	/* Init Jool's submodules. */
	error = bib_setup();
	if (error)
		goto bib_fail;
	error = joold_setup();
	if (error)
		goto joold_fail;
	error = rfc6056_setup();
	if (error)
		goto rfc6056_fail;
	error = xlator_setup();
	if (error)
		goto xlator_fail;
	error = nlhandler_setup();
	if (error)
		goto nlhandler_fail;
	error = jtimer_setup();
	if (error)
		goto jtimer_fail;

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 9999, 0)
	/* Hook Jool to Netfilter. */
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_fail;
#endif

	iptables_error = xt_register_targets(targets, ARRAY_SIZE(targets));
	if (iptables_error) {
		log_warn("Error code %d while trying to register the iptables targets.\n"
				"iptables NAT64 Jool will not be available.",
				iptables_error);
	}

	/* Yay */
	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return error;

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 9999, 0)
nf_register_hooks_fail:
	jtimer_teardown();
#endif
jtimer_fail:
	nlhandler_teardown();
nlhandler_fail:
	xlator_teardown();
xlator_fail:
	rfc6056_teardown();
rfc6056_fail:
	joold_teardown();
joold_fail:
	bib_teardown();
bib_fail:
	return error;
}

static void __exit jool_exit(void)
{
	if (!iptables_error)
		xt_unregister_targets(targets, ARRAY_SIZE(targets));

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 9999, 0)
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));
#endif

	jtimer_teardown();
	nlhandler_teardown();
	xlator_teardown();
	rfc6056_teardown();
	joold_teardown();
	bib_teardown();

#ifdef JKMEMLEAK
	wkmalloc_print_leaks();
	wkmalloc_teardown();
#endif

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_init);
module_exit(jool_exit);
