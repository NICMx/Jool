#include "nat64/mod/common/kernel_hook.h"

#include <linux/module.h>

#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/nl_handler.h"
#include "nat64/mod/stateless/pool.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateless IP/ICMP Translation (RFC 7915)");
MODULE_VERSION(JOOL_VERSION_STR);

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
static bool no_instance;
module_param(no_instance, bool, 0);
MODULE_PARM_DESC(no_instance, "Prevent an instance from being added to the current namespace during the modprobe.");

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
		.name       = IPTABLES_SIIT_MODULE_NAME,
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = target_ipv6,
		.checkentry = target_checkentry,
		.targetsize = XT_ALIGN(sizeof(struct target_info)),
		.me         = THIS_MODULE,
	}, {
		.name       = IPTABLES_SIIT_MODULE_NAME,
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

static int add_instance(void)
{
	struct xlator jool;
	int error;

	if (no_instance)
		return 0;

	error = xlator_add(FW_NETFILTER, INAME_DEFAULT, &jool);
	if (error)
		return error;

	jool.global->cfg.enabled = !disabled;
	error = pool6_add_str(jool.pool6, &pool6, pool6 ? 1 : 0);
	if (error)
		goto end;
	error = pool_add_str(jool.siit.blacklist, blacklist, blacklist_size);
	if (error)
		goto end;
	error = pool_add_str(jool.siit.pool6791, pool6791, pool6791_size);
	/* Fall through. */

end:
	xlator_put(&jool);
	return error;
}

static int __init jool_init(void)
{
	int error;

	log_debug("Inserting %s...", xlat_get_name());

	/* Init Jool's submodules. */
	error = xlator_setup();
	if (error)
		goto xlator_fail;
	error = nlhandler_setup();
	if (error)
		goto nlhandler_fail;

	/* This needs to be last! (except for the hook registering.) */
	error = add_instance();
	if (error)
		goto instance_fail;

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 9999, 0)
	/*
	* Hook Jool to Netfilter.
	* (This has to be done in add_instance() on high kernels.)
	*/
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_fail;
#endif

	iptables_error = xt_register_targets(targets, ARRAY_SIZE(targets));
	if (iptables_error) {
		log_warn("Error code %d while trying to register the iptables targets.\n"
				"iptables SIIT Jool will not be available.",
				iptables_error);
	}

	/* Yay */
	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return 0;

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 9999, 0)
nf_register_hooks_fail:
	xlator_rm(INAME_DEFAULT);
#endif
instance_fail:
	nlhandler_teardown();
nlhandler_fail:
	xlator_teardown();
xlator_fail:
	return error;
}

static void __exit jool_exit(void)
{
	if (!iptables_error)
		xt_unregister_targets(targets, ARRAY_SIZE(targets));

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 9999, 0)
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));
#endif

	nlhandler_teardown();
	xlator_teardown();

#ifdef JKMEMLEAK
	wkmalloc_print_leaks();
	wkmalloc_teardown();
#endif

	log_info("%s v" JOOL_VERSION_STR " module removed.", xlat_get_name());
}

module_init(jool_init);
module_exit(jool_exit);
