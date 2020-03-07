#include "mod/common/nl/nl_handler.h"

#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/genetlink.h>

#include "common/types.h"
#include "mod/common/init.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/address.h"
#include "mod/common/nl/atomic_config.h"
#include "mod/common/nl/bib.h"
#include "mod/common/nl/blacklist4.h"
#include "mod/common/nl/eam.h"
#include "mod/common/nl/global.h"
#include "mod/common/nl/instance.h"
#include "mod/common/nl/joold.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/nl/pool4.h"
#include "mod/common/nl/session.h"
#include "mod/common/nl/stats.h"

static int pre_handle_request(const struct genl_ops *ops, struct sk_buff *skb,
		struct genl_info *info)
{
	error_pool_activate();
	return 0;
}

static void post_handle_request(const struct genl_ops *ops, struct sk_buff *skb,
		struct genl_info *info)
{
	error_pool_deactivate();
}

struct nla_policy const jool_policy[RA_COUNT] = {
	[RA_ADDR_QUERY] = { .type = NLA_NESTED },
	[RA_GLOBALS] = { .type = NLA_NESTED },
	[RA_BL4_ENTRIES] = { .type = NLA_NESTED },
	[RA_EAMT_ENTRIES] = { .type = NLA_NESTED },
	[RA_POOL4_ENTRIES] = { .type = NLA_NESTED },
	[RA_BIB_ENTRIES] = { .type = NLA_NESTED },
	[RA_SESSION_ENTRIES] = { .type = NLA_NESTED },
	[RA_OFFSET] = { .type = NLA_NESTED },
	[RA_OPERAND] = { .type = NLA_NESTED },
	[RA_PROTO] = { .type = NLA_U8 },
	[RA_ATOMIC_INIT] = { .type = NLA_U8 },
	[RA_ATOMIC_END] = { .type = NLA_UNSPEC, .len = 0 },
};

#if LINUX_VERSION_AT_LEAST(5, 2, 0, 9999, 0)
#define JOOL_POLICY
#else
#define JOOL_POLICY .policy = jool_policy,
#endif

static const struct genl_ops ops[] = {
	{
		.cmd = JOP_INSTANCE_FOREACH,
		.doit = handle_instance_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_INSTANCE_ADD,
		.doit = handle_instance_add,
		JOOL_POLICY
	}, {
		.cmd = JOP_INSTANCE_HELLO,
		.doit = handle_instance_hello,
		JOOL_POLICY
	}, {
		.cmd = JOP_INSTANCE_RM,
		.doit = handle_instance_rm,
		JOOL_POLICY
	}, {
		.cmd = JOP_INSTANCE_FLUSH,
		.doit = handle_instance_flush,
		JOOL_POLICY
	}, {
		.cmd = JOP_ADDRESS_QUERY64,
		.doit = handle_address_query64,
		JOOL_POLICY
	}, {
		.cmd = JOP_ADDRESS_QUERY46,
		.doit = handle_address_query46,
		JOOL_POLICY
	}, {
		.cmd = JOP_STATS_FOREACH,
		.doit = handle_stats_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_GLOBAL_FOREACH,
		.doit = handle_global_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_GLOBAL_UPDATE,
		.doit = handle_global_update,
		JOOL_POLICY
	}, {
		.cmd = JOP_EAMT_FOREACH,
		.doit = handle_eamt_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_EAMT_ADD,
		.doit = handle_eamt_add,
		JOOL_POLICY
	}, {
		.cmd = JOP_EAMT_RM,
		.doit = handle_eamt_rm,
		JOOL_POLICY
	}, {
		.cmd = JOP_EAMT_FLUSH,
		.doit = handle_eamt_flush,
		JOOL_POLICY
	}, {
		.cmd = JOP_BL4_FOREACH,
		.doit = handle_blacklist4_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_BL4_ADD,
		.doit = handle_blacklist4_add,
		JOOL_POLICY
	}, {
		.cmd = JOP_BL4_RM,
		.doit = handle_blacklist4_rm,
		JOOL_POLICY
	}, {
		.cmd = JOP_BL4_FLUSH,
		.doit = handle_blacklist4_flush,
		JOOL_POLICY
	}, {
		.cmd = JOP_POOL4_FOREACH,
		.doit = handle_pool4_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_POOL4_ADD,
		.doit = handle_pool4_add,
		JOOL_POLICY
	}, {
		.cmd = JOP_POOL4_RM,
		.doit = handle_pool4_rm,
		JOOL_POLICY
	}, {
		.cmd = JOP_POOL4_FLUSH,
		.doit = handle_pool4_flush,
		JOOL_POLICY
	}, {
		.cmd = JOP_BIB_FOREACH,
		.doit = handle_bib_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_BIB_ADD,
		.doit = handle_bib_add,
		JOOL_POLICY
	}, {
		.cmd = JOP_BIB_RM,
		.doit = handle_bib_rm,
		JOOL_POLICY
	}, {
		.cmd = JOP_SESSION_FOREACH,
		.doit = handle_session_foreach,
		JOOL_POLICY
	}, {
		.cmd = JOP_FILE_HANDLE,
		.doit = handle_atomconfig_request,
		JOOL_POLICY
	}
};

static struct genl_multicast_group mc_groups[] = {
	{
		.name = GNL_JOOLD_MULTICAST_GRP_NAME,
#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)
		.id = JOOLD_MC_ID,
#endif
	},
};

static struct genl_family jool_family = {
#if LINUX_VERSION_LOWER_THAN(4, 10, 0, 7, 5)
	/* This variable became "private" on kernel 4.10. */
	.id = GENL_ID_GENERATE,
#endif
	.hdrsize = sizeof(struct joolnl_hdr),
	/* This is initialized below. See register_family(). */
	/* .name = GNL_JOOL_FAMILY_NAME, */
	.version = 2,
	.maxattr = RA_MAX,
	.netnsok = true,
	.parallel_ops = false,
#if LINUX_VERSION_AT_LEAST(5, 2, 0, 9999, 0)
	.policy = jool_policy,
#endif
	.pre_doit = pre_handle_request,
	.post_doit = post_handle_request,

#if LINUX_VERSION_AT_LEAST(4, 10, 0, 7, 5)
	/*
	 * "module" was added in Linux 3.11 (commit
	 * 33c6b1f6b154894321f5734e50c66621e9134e7e). However, it seems to be
	 * supposed to be private; it is set automatically during the
	 * genl_register* functions. It is also sorta grouped with the other
	 * private members.
	 * "module" becomes our responsibility during commit
	 * 489111e5c25b93be80340c3113d71903d7c82136, which is headed towards
	 * Linux 4.10.
	 * The same can be said about the remaining fields, though they are more
	 * clearly private until 4.10.
	 */
	.module = THIS_MODULE,
	.ops = ops,
	.n_ops = ARRAY_SIZE(ops),
	.mcgrps = mc_groups,
	.n_mcgrps = ARRAY_SIZE(mc_groups),
#endif
};

static int register_family(void)
{
	int error;

	log_debug("Registering Generic Netlink family...");

	strcpy(jool_family.name, GNL_JOOL_FAMILY);

#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)

	error = genl_register_family_with_ops(&jool_family, ops,
			ARRAY_SIZE(ops));
	if (error) {
		log_err("Couldn't register family!");
		return error;
	}

	error = genl_register_mc_group(&jool_family, &(mc_groups[0]));
	if (error) {
		log_err("Couldn't register multicast group!");
		return error;
	}

#elif LINUX_VERSION_LOWER_THAN(4, 10, 0, 7, 5)
	error = genl_register_family_with_ops_groups(&jool_family, ops,
			mc_groups);
	if (error) {
		log_err("Family registration failed: %d", error);
		return error;
	}
#else
	error = genl_register_family(&jool_family);
	if (error) {
		log_err("Family registration failed: %d", error);
		return error;
	}
#endif

	nlcore_setup(&jool_family, &mc_groups[0]);
	return 0;
}

int nlhandler_setup(void)
{
	error_pool_setup();
	return register_family();
}

void nlhandler_teardown(void)
{
	genl_unregister_family(&jool_family);
	error_pool_teardown();
}
