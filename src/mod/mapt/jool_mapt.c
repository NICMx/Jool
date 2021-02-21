#include "mod/common/init.h"

#include <linux/module.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>

#include "common/iptables.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/kernel_hook.h"
#include "mod/common/xlator.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("MAP-T (RFC 7599)");
MODULE_VERSION(JOOL_VERSION_STR);

static int iptables_error;

/** iptables module registration object */
static struct xt_target targets[] = {
	{
		.name       = IPTABLES_MAPT_MODULE_NAME,
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = target_ipv6,
		.checkentry = target_checkentry,
		.targetsize = XT_ALIGN(sizeof(struct target_info)),
		.me         = THIS_MODULE,
	}, {
		.name       = IPTABLES_MAPT_MODULE_NAME,
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = target_ipv4,
		.checkentry = target_checkentry,
		.targetsize = XT_ALIGN(sizeof(struct target_info)),
		.me         = THIS_MODULE,
	},
};

static void flush_net(struct net *ns)
{
	jool_xlator_flush_net(ns, XT_MAPT);
}

static void flush_batch(struct list_head *net_exit_list)
{
	jool_xlator_flush_batch(net_exit_list, XT_MAPT);
}

/** Namespace-aware network operation registration object */
static struct pernet_operations joolns_ops = {
	.exit = flush_net,
	.exit_batch = flush_batch,
};

static void defrag_enable(struct net *ns)
{
#if LINUX_VERSION_AT_LEAST(4, 10, 0, 8, 0)
	nf_defrag_ipv4_enable(ns);
	nf_defrag_ipv6_enable(ns);
#else
	nf_defrag_ipv4_enable();
	nf_defrag_ipv6_enable();
#endif
}

static int __init mapt_init(void)
{
	int error;

	pr_debug("Inserting MAPT Jool...\n");
	/* Careful with the order */

	error = register_pernet_subsys(&joolns_ops);
	if (error)
		return error;

	iptables_error = xt_register_targets(targets, ARRAY_SIZE(targets));
	if (iptables_error) {
		log_warn("Error code %d while trying to register the iptables targets.\n"
				"iptables SIIT Jool will not be available.",
				iptables_error);
	}

	/* MAP-T instances can now function properly; unlock them. */
	error = jool_mapt_get(defrag_enable);
	if (error) {
		if (!iptables_error)
			xt_unregister_targets(targets, ARRAY_SIZE(targets));
		unregister_pernet_subsys(&joolns_ops);
		return error;
	}

	pr_info("MAPT Jool v" JOOL_VERSION_STR " module inserted.\n");
	return error;
}

static void __exit mapt_exit(void)
{
	jool_mapt_put();
	if (!iptables_error)
		xt_unregister_targets(targets, ARRAY_SIZE(targets));
	unregister_pernet_subsys(&joolns_ops);
	pr_info("MAPT Jool v" JOOL_VERSION_STR " module removed.\n");
}

module_init(mapt_init);
module_exit(mapt_exit);
