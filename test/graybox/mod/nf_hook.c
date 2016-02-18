#include "types.h"
#include "config.h"
#include "receiver.h"
#include "skb_ops.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include "device_name.h"
#include "nat64/mod/common/nf_wrapper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION(MODULE_NAME " (GRAYBOX_TESTS_FOR_JOOL)");

static char *banner = "\n"
	" =============== Graybox tests for Jool (NAT64) ==============\n"
	" ================= Packet Sender and Receiver ================\n";


static NF_CALLBACK(hook_ipv4, skb)
{
	return receiver_incoming_skb4(skb);
}

static NF_CALLBACK(hook_ipv6, skb)
{
	return receiver_incoming_skb6(skb);
}

static struct nf_hook_ops nfho[] = {
	{
		.hook = hook_ipv6,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
	},
	{
		.hook = hook_ipv4,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
	}
};

static int __init graybox_init(void)
{
	int i, error;

	log_debug("%s", banner);
	log_debug("Inserting the module...");

	/* Init Packet sender's submodules. */
	error = config_init();
	if (error)
		goto config_failure;

	error = dev_init();
	if (error)
		goto device_failure;

	error = receiver_init();
	if (error)
		goto receiver_failure;

	error = skbops_init();
	if (error)
		goto skbops_failure;

	/* Hook Jool to Netfilter. */
	for (i = 0; i < ARRAY_SIZE(nfho); i++)
		nfho[i].priority = NF_IP_PRI_FIRST + 25;

	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info(MODULE_NAME " module inserted.\n");
	return error;


nf_register_hooks_failure:
	skbops_destroy();

skbops_failure:
	receiver_destroy();

receiver_failure:
	dev_destroy();

device_failure:
	config_destroy();

config_failure:
	return error;
}

static void __exit graybox_exit(void)
{
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	skbops_destroy();
	receiver_destroy();
	dev_destroy();
	config_destroy();

	log_info(MODULE_NAME " module removed.");
}

module_init(graybox_init);
module_exit(graybox_exit);
