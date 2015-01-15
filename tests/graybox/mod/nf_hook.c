#include "types.h"
#include "config.h"
#include "receiver.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION(MODULE_NAME " (GRAYBOX_TESTS_FOR_JOOL)");

static char *banner = "\n"
	" =============================================================  \n"
	" =============================================================  \n"
	" =============== Graybox tests for Jool (NAT64) ==============  \n"
	" ================= Packet Sender and Receiver ================  \n"
	" =============================================================  \n"
	" =============================================================  \n";


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define HOOK_ARG_TYPE const struct nf_hook_ops *
#else
#define HOOK_ARG_TYPE unsigned int
#endif

static unsigned int hook_ipv4(HOOK_ARG_TYPE hook, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return receiver_incoming_skb4(skb);
}

static unsigned int hook_ipv6(HOOK_ARG_TYPE hook, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	return receiver_incoming_skb6(skb);
}

static struct nf_hook_ops nfho[] = {
	{
		.hook = hook_ipv6,
		.pf = PF_INET6,
		.hooknum = NF_INET_PRE_ROUTING
	},
	{
		.hook = hook_ipv4,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING
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

	error = receiver_init();
	if (error)
		goto receiver_failure;

	/* Hook Jool to Netfilter. */
	for (i = 0; i < ARRAY_SIZE(nfho); i++) {
		nfho[i].owner = NULL;
		nfho[i].priority = NF_IP_PRI_FIRST + 25;
	}

	error = nf_register_hooks(nfho, ARRAY_SIZE(nfho));
	if (error)
		goto nf_register_hooks_failure;

	/* Yay */
	log_info(MODULE_NAME " module inserted.");
	return error;

nf_register_hooks_failure:
	receiver_destroy();

receiver_failure:
	config_destroy();

config_failure:
	return error;
}

static void __exit graybox_exit(void)
{
	/* Release the hook. */
	nf_unregister_hooks(nfho, ARRAY_SIZE(nfho));

	receiver_destroy();
	config_destroy();

	log_info(MODULE_NAME " module removed.");
}

module_init(graybox_init);
module_exit(graybox_exit);
