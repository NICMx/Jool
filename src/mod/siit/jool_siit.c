#include "mod/common/init.h"

#include <linux/module.h>
#include "common/config.h"
#include "mod/common/kernel_hook.h"
#include "mod/common/log.h"

MODULE_LICENSE(JOOL_LICENSE);
MODULE_AUTHOR("NIC-ITESM");
MODULE_DESCRIPTION("Stateless IP/ICMP Translation (RFC 7915)");
MODULE_VERSION(JOOL_VERSION_STR);

static int iptables_error;

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

static int __init siit_init(void)
{
	int error;

	pr_debug("Inserting SIIT Jool...\n");

	error = jool_siit_get();
	if (error)
		return error;

	iptables_error = xt_register_targets(targets, ARRAY_SIZE(targets));
	if (iptables_error) {
		log_warn("Error code %d while trying to register the iptables targets.\n"
				"iptables SIIT Jool will not be available.",
				iptables_error);
	}

	nft_setup();

	pr_info("SIIT Jool v" JOOL_VERSION_STR " module inserted.\n");
	return 0;
}

static void __exit siit_exit(void)
{
	nft_teardown();
	if (!iptables_error)
		xt_unregister_targets(targets, ARRAY_SIZE(targets));
	jool_siit_put();
	pr_info("SIIT Jool v" JOOL_VERSION_STR " module removed.\n");
}

module_init(siit_init);
module_exit(siit_exit);
