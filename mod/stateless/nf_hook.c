#include "nat64/mod/common/nf_hook.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/core.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/nf_wrapper.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/nl_handler.h"
#include "nat64/mod/stateless/pool.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateless IP/ICMP Translation (RFC 6145)");
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

	error = xlator_add(&jool);
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

	/* Yay */
	log_info("%s v" JOOL_VERSION_STR " module inserted.", xlat_get_name());
	return 0;

#if LINUX_VERSION_LOWER_THAN(4, 13, 0, 9999, 0)
nf_register_hooks_fail:
	xlator_rm();
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
