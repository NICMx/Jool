#include "mod/common/nl/nl_handler.h"

#include <linux/mutex.h>
#include <linux/genetlink.h>

#include "common/types.h"
#include "mod/common/init.h"
#include "mod/common/linux_version.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/address.h"
#include "mod/common/nl/atomic_config.h"
#include "mod/common/nl/bib.h"
#include "mod/common/nl/denylist4.h"
#include "mod/common/nl/eam.h"
#include "mod/common/nl/fmr.h"
#include "mod/common/nl/global.h"
#include "mod/common/nl/instance.h"
#include "mod/common/nl/joold.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/pool4.h"
#include "mod/common/nl/session.h"
#include "mod/common/nl/stats.h"

#if LINUX_VERSION_AT_LEAST(0, 0, 0, 7, 1)
#define _CONST const
#else
#define _CONST
#endif

static struct nla_policy const jool_policy[JNLAR_COUNT] = {
	[JNLAR_ADDR_QUERY] = { .type = NLA_BINARY },
	[JNLAR_GLOBALS] = { .type = NLA_NESTED },
	[JNLAR_BL4_ENTRIES] = { .type = NLA_NESTED },
	[JNLAR_EAMT_ENTRIES] = { .type = NLA_NESTED },
	[JNLAR_POOL4_ENTRIES] = { .type = NLA_NESTED },
	[JNLAR_BIB_ENTRIES] = { .type = NLA_NESTED },
	[JNLAR_SESSION_ENTRIES] = { .type = NLA_NESTED },
	[JNLAR_FMRT_ENTRIES] = { .type = NLA_NESTED },
	[JNLAR_OFFSET] = { .type = NLA_NESTED },
	[JNLAR_OFFSET_U8] = { .type = NLA_U8 },
	[JNLAR_OPERAND] = { .type = NLA_NESTED },
	[JNLAR_PROTO] = { .type = NLA_U8 },
	[JNLAR_ATOMIC_INIT] = { .type = NLA_U8 },
	[JNLAR_ATOMIC_END] = { .type = NLA_BINARY, .len = 0 },
};

#if LINUX_VERSION_AT_LEAST(5, 2, 0, 8, 0)
#define JOOL_POLICY
#else
#define JOOL_POLICY .policy = jool_policy,
#endif

static _CONST struct genl_ops ops[] = {
	{
		.cmd = JNLOP_INSTANCE_FOREACH,
		.doit = handle_instance_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_INSTANCE_ADD,
		.doit = handle_instance_add,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_INSTANCE_HELLO,
		.doit = handle_instance_hello,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_INSTANCE_RM,
		.doit = handle_instance_rm,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_INSTANCE_FLUSH,
		.doit = handle_instance_flush,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_ADDRESS_QUERY64,
		.doit = handle_address_query64,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_ADDRESS_QUERY46,
		.doit = handle_address_query46,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_STATS_FOREACH,
		.doit = handle_stats_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_GLOBAL_FOREACH,
		.doit = handle_global_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_GLOBAL_UPDATE,
		.doit = handle_global_update,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_EAMT_FOREACH,
		.doit = handle_eamt_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_EAMT_ADD,
		.doit = handle_eamt_add,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_EAMT_RM,
		.doit = handle_eamt_rm,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_EAMT_FLUSH,
		.doit = handle_eamt_flush,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_BL4_FOREACH,
		.doit = handle_denylist4_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_BL4_ADD,
		.doit = handle_denylist4_add,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_BL4_RM,
		.doit = handle_denylist4_rm,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_BL4_FLUSH,
		.doit = handle_denylist4_flush,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_POOL4_FOREACH,
		.doit = handle_pool4_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_POOL4_ADD,
		.doit = handle_pool4_add,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_POOL4_RM,
		.doit = handle_pool4_rm,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_POOL4_FLUSH,
		.doit = handle_pool4_flush,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_BIB_FOREACH,
		.doit = handle_bib_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_BIB_ADD,
		.doit = handle_bib_add,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_BIB_RM,
		.doit = handle_bib_rm,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_SESSION_FOREACH,
		.doit = handle_session_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_FMRT_FOREACH,
		.doit = handle_fmrt_foreach,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_FMRT_ADD,
		.doit = handle_fmrt_add,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_FMRT_RM,
		.doit = handle_fmrt_rm,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_FMRT_FLUSH,
		.doit = handle_fmrt_flush,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_FILE_HANDLE,
		.doit = handle_atomconfig_request,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_JOOLD_ADD,
		.doit = handle_joold_add,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_JOOLD_ADVERTISE,
		.doit = handle_joold_advertise,
		JOOL_POLICY
	}, {
		.cmd = JNLOP_JOOLD_ACK,
		.doit = handle_joold_ack,
		JOOL_POLICY
	}
};

static struct genl_multicast_group mc_groups[] = {
	{
		.name = JOOLNL_MULTICAST_GRP_NAME,
	},
};

static struct genl_family jool_family = {
#if LINUX_VERSION_LOWER_THAN(4, 10, 0, 7, 5)
	/* This variable became "private" on kernel 4.10. */
	.id = GENL_ID_GENERATE,
#endif
	.hdrsize = sizeof(struct joolnlhdr),
	.name = JOOLNL_FAMILY,
	.version = 2,
	.maxattr = JNLAR_MAX,
	.netnsok = true,
	.parallel_ops = false,
#if LINUX_VERSION_AT_LEAST(5, 2, 0, 8, 0)
	.policy = jool_policy,
#endif

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

	pr_debug("Registering Generic Netlink family...\n");

#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)

	error = genl_register_family_with_ops(&jool_family, ops,
			ARRAY_SIZE(ops));
	if (error) {
		pr_err("Couldn't register family!\n");
		return error;
	}

	error = genl_register_mc_group(&jool_family, &(mc_groups[0]));
	if (error) {
		pr_err("Couldn't register multicast group!\n");
		return error;
	}

#elif LINUX_VERSION_LOWER_THAN(4, 10, 0, 7, 5)
	error = genl_register_family_with_ops_groups(&jool_family, ops,
			mc_groups);
	if (error) {
		pr_err("Family registration failed: %d\n", error);
		return error;
	}
#else
	error = genl_register_family(&jool_family);
	if (error) {
		pr_err("Family registration failed: %d\n", error);
		return error;
	}
#endif

	return 0;
}

int nlhandler_setup(void)
{
	return register_family();
}

void nlhandler_teardown(void)
{
	genl_unregister_family(&jool_family);
}

#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)
u32 jnl_gid(void)
{
	return mc_groups[0].id;
}
#endif

struct genl_family *jnl_family(void)
{
	return &jool_family;
}
EXPORT_UNIT_SYMBOL(jnl_family)
