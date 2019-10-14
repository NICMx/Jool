#include "mod/common/init.h"

#include <linux/module.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>

#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/kernel_hook.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateful NAT64 (RFC 6146)");
MODULE_VERSION(JOOL_VERSION_STR);

static char const *banner = "\n"
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

static int iptables_error;

/** iptables module registration object */
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

static void defrag_enable(struct net *ns)
{
#if LINUX_VERSION_AT_LEAST(4, 10, 0, 9999, 0)
	nf_defrag_ipv4_enable(ns);
	nf_defrag_ipv6_enable(ns);
#else
	nf_defrag_ipv4_enable();
	nf_defrag_ipv6_enable();
#endif
}

static int __init nat64_init(void)
{
	int error;

	pr_debug("%s", banner);
	pr_debug("Inserting NAT64 Jool...\n");

	error = jool_nat64_get(defrag_enable);
	if (error)
		return error;

	iptables_error = xt_register_targets(targets, ARRAY_SIZE(targets));
	if (iptables_error) {
		log_warn("Error code %d while trying to register the iptables targets.\n"
				"iptables SIIT Jool will not be available.",
				iptables_error);
	}

	pr_info("NAT64 Jool v" JOOL_VERSION_STR " module inserted.\n");
	return error;
}

static void __exit nat64_exit(void)
{
	if (!iptables_error)
		xt_unregister_targets(targets, ARRAY_SIZE(targets));
	jool_nat64_put();
	pr_info("NAT64 Jool v" JOOL_VERSION_STR " module removed.\n");
}

module_init(nat64_init);
module_exit(nat64_exit);
