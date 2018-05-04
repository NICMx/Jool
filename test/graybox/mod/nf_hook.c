#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include "nat64/common/types.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/nf_wrapper.h"

#include "expecter.h"
#include "nl_handler.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Graybox test gimmic for Jool.");

static NF_CALLBACK(hook_cb, skb)
{
	return expecter_handle_pkt(skb);
}

static struct nf_hook_ops nfho[] = {
	{
		.hook = hook_cb,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP6_PRI_FIRST + 25,
	},
	{
		.hook = hook_cb,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST + 25,
	}
};

static int graybox_init(void)
{
	int error;

	log_debug("Inserting the module...");

	error = nlhandler_setup();
	if (error)
		return error;
	error_pool_setup();
	expecter_setup();

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	error = nf_register_net_hooks(&init_net, nfho, ARRAY_SIZE(nfho));
#else
	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
#endif
	if (error) {
		expecter_teardown();
		error_pool_teardown();
		nlhandler_teardown();
		return error;
	}

	log_info("%s module inserted.\n", xlat_get_name());
	return error;
}

static void graybox_exit(void)
{
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	nf_unregister_net_hooks(&init_net, nfho, ARRAY_SIZE(nfho));
#else
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));
#endif

	expecter_teardown();
	error_pool_teardown();
	nlhandler_teardown();

	log_info("%s module removed.", xlat_get_name());
}

module_init(graybox_init);
module_exit(graybox_exit);
