#include "nl/nl-handler.h"

#include <net/genetlink.h>
#include "linux-version.h"
#include "nl-protocol.h"
#include "nl/nl-atomic-config.h"
#include "nl/nl-bib.h"
#include "nl/nl-eam.h"
#include "nl/nl-global.h"
#include "nl/nl-instance.h"
#include "nl/nl-joold.h"
#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nl/nl-pool4.h"
#include "nl/nl-session.h"

/* Common nla_policy predicates */
#define NPP_ADDR6 { .type = NLA_BINARY, .len = 16 }
#define NPP_ADDR4 { .type = NLA_BINARY, .len = 4 }
#define NPP_PORT { .type = NLA_U16 }
#define NPP_PREFIXLEN { .type = NLA_U8 }
#define NPP_BOOL { .type = NLA_U8 }

/* Common nla_policy definitions */
/* TODO null chara included in IF_NAMSIZ? */
#define NPD_INSTANCE_NAME [JNLA_INSTANCE_NAME] = { .type = NLA_STRING, .len = IFNAMSIZ }
#define NPD_INSTANCE_TYPE [JNLA_INSTANCE_TYPE] = { .type = NLA_U8 }

#define NPD_L4PROTO [JNLA_L4PROTO] = { .type = NLA_U8 }
#define NPD_SADDR6 [JNLA_SADDR6] = NPP_ADDR6
#define NPD_SADDR4 [JNLA_SADDR4] = NPP_ADDR4
#define NPD_SPORT6 [JNLA_SPORT6] = NPP_PORT
#define NPD_SPORT4 [JNLA_SPORT4] = NPP_PORT

#define NPD_PREFIXADDR6 [JNLA_PREFIXADDR6] = NPP_ADDR6
#define NPD_PREFIXLEN6 [JNLA_PREFIXLEN6] = NPP_PREFIXLEN
#define NPD_PREFIXADDR4 [JNLA_PREFIXADDR4] = NPP_ADDR4
#define NPD_PREFIXLEN4 [JNLA_PREFIXLEN4] = NPP_PREFIXLEN

#define NPD_MARK [JNLA_MARK] = { .type = NLA_U32 }
#define NPD_FORCE [JNLA_FORCE] = NPP_BOOL
#define NPD_QUICK [JNLA_QUICK] = NPP_BOOL
#define NPD_ITERATIONS [JNLA_ITERATIONS] = { .type = NLA_U32 }
#define NPD_ITERATION_FLAGS [JNLA_ITERATION_FLAGS] = { .type = NLA_U8 }

/* Common nla_policy groups */

#define NPG_SRCT6 NPD_SADDR6, NPD_SPORT6 /* "SouRCe Transport address ipv6" */
#define NPG_SRCT4 NPD_SADDR4, NPD_SPORT4 /* "SouRCe Transport address ipv4" */
#define NPG_BIB_ENTRY NPD_L4PROTO, NPG_SRCT6, NPG_SRCT4
#define NPG_POOL4_ENTRY NPD_L4PROTO, NPG_SRCT4

static struct nla_policy policy_instance_add[__JNLA_MAX] = {
	NPD_INSTANCE_NAME,
	NPD_INSTANCE_TYPE,
};

static struct nla_policy policy_instance_rm[__JNLA_MAX] = {
	NPD_INSTANCE_NAME,
};
/*
static struct nla_policy policy_eamt_foreach[__JNLA_MAX] = {
	INSTANCE_NAME,
	ADDR4,
	PREFIXLEN,
};

static struct nla_policy policy_eamt_add[__JNLA_MAX] = {
	INSTANCE_NAME,
	ADDR6,
	ADDR4,
	PREFIXLEN,
	FORCE,
};

static struct nla_policy policy_eamt_rm[__JNLA_MAX] = {
	INSTANCE_NAME,
	ADDR6,
	ADDR4,
	PREFIXLEN,
};

static struct nla_policy policy_eamt_flush[__JNLA_MAX] = {
	INSTANCE_NAME,
};

static struct nla_policy policy_pool4_foreach[__JNLA_MAX] = {
	INSTANCE_NAME,
	MARK,
	L4PROTO,
	ADDR4,
	PORT,
};

static struct nla_policy policy_pool4_add[__JNLA_MAX] = {
	INSTANCE_NAME,
	MARK,
	ITERATIONS,
	ITERATION_FLAGS,
	L4PROTO,
	ADDR4,
	PREFIXLEN,
	PORT,
};

static struct nla_policy policy_pool4_rm[__JNLA_MAX] = {
	INSTANCE_NAME,
	MARK,
	L4PROTO,
	ADDR4,
	PREFIXLEN,
	PORT,
	QUICK,
};

static struct nla_policy policy_pool4_flush[__JNLA_MAX] = {
	INSTANCE_NAME,
	QUICK,
};
*/
static struct nla_policy policy_bib_foreach[__JNLA_MAX] = {
	NPD_INSTANCE_NAME,
	NPD_L4PROTO,
	NPG_SRCT4,
};

static struct nla_policy policy_bib_add[__JNLA_MAX] = {
	NPD_INSTANCE_NAME,
	NPG_BIB_ENTRY,
};

static struct nla_policy policy_bib_rm[__JNLA_MAX] = {
	NPD_INSTANCE_NAME,
	NPG_BIB_ENTRY,
};
/*
static struct nla_policy policy_session_foreach[__JNLA_MAX] = {
	INSTANCE_NAME,
	L4PROTO,
	ADDR4,
	PORT,
};
*/
static struct genl_ops jool_genl_ops[] = {
	{
		.cmd = JGNC_INSTANCE_ADD,
		.policy = policy_instance_add,
		.doit = handle_instance_add,
	}, {
		.cmd = JGNC_INSTANCE_RM,
		.policy = policy_instance_rm,
		.doit = handle_instance_rm,
	}, {
	/*	.cmd = JGNC_EAMT_FOREACH,
		.policy = policy_eamt_foreach,
		.doit = handle_eamt_foreach,
	}, {
		.cmd = JGNC_EAMT_ADD,
		.policy = policy_eamt_add,
		.doit = handle_eamt_add,
	}, {
		.cmd = JGNC_EAMT_RM,
		.policy = policy_eamt_rm,
		.doit = handle_eamt_rm,
	}, {
		.cmd = JGNC_EAMT_FLUSH,
		.policy = policy_eamt_flush,
		.doit = handle_eamt_flush,
	}, {
		.cmd = JGNC_POOL4_FOREACH,
		.policy = policy_pool4_foreach,
		.doit = handle_pool4_foreach,
	}, {
		.cmd = JGNC_POOL4_ADD,
		.policy = policy_pool4_add,
		.doit = handle_pool4_add,
	}, {
		.cmd = JGNC_POOL4_RM,
		.policy = policy_pool4_rm,
		.doit = handle_pool4_rm,
	}, {
		.cmd = JGNC_POOL4_FLUSH,
		.policy = policy_pool4_flush,
		.doit = handle_pool4_flush,
	}, {*/
		.cmd = JGNC_BIB_FOREACH,
		.policy = policy_bib_foreach,
		.doit = handle_bib_foreach,
	}, {
		.cmd = JGNC_BIB_ADD,
		.policy = policy_bib_add,
		.doit = handle_bib_add,
	}, {
		.cmd = JGNC_BIB_RM,
		.policy = policy_bib_rm,
		.doit = handle_bib_rm,
	/*}, {
		.cmd = JGNC_SESSION_FOREACH,
		.policy = policy_session_foreach,
		.doit = handle_session_foreach,*/
	}
};

static int jnl_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
		struct genl_info *info)
{
	log_debug("===============================================");
	log_debug("Received a request from userspace.");

	errormsg_enable(); /* Mutex lock */
	return 0;
}

static void jnl_post_doit(const struct genl_ops *ops, struct sk_buff *skb,
		struct genl_info *info)
{
	errormsg_disable(); /* Mutex unlock */
}

static struct genl_family jool_family = {
#if LINUX_VERSION_LOWER_THAN(4, 10, 0, 9999, 0)
	/* This variable became "private" on kernel 4.10. */
	.id = GENL_ID_GENERATE,
#endif
	.hdrsize = JNL_HDR_LEN,
	/* This is initialized below. See register_family(). */
	/* .name = GNL_JOOL_FAMILY_NAME, */
	/**
	 * TODO heads up: Even though version is declared as an unsigned int
	 * in this structure, it is actually meant to be 8-bits.
	 * This is far from enough for us, so the real version number is going
	 * to have to be included as an attribute.
	 */
	.version = JOOL_VERSION_MAJOR,
	.maxattr = __JNLA_MAX,
	.netnsok = true,
	/*
	 * In kernel 3.10, they added a variable here called "parallel_ops".
	 * Documentation about it can be found in Linux's commit
	 * def3117493eafd9dfa1f809d861e0031b2cc8a07.
	 * It appears to be an attempt to free genetlink users from the task of
	 * locking.
	 * We need to support older kernels, so we need to lock anyway, so this
	 * feature is of no use to us.
	 */
	.pre_doit = jnl_pre_doit,
	.post_doit = jnl_post_doit,

#if LINUX_VERSION_AT_LEAST(4, 10, 0, 9999, 0)
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

	strcpy(jool_family.name, GNL_JOOL_FAMILY_NAME);

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

#elif LINUX_VERSION_LOWER_THAN(4, 10, 0, 9999, 0)
	error = genl_register_family_with_ops(&jool_family, jool_genl_ops);
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

	nlcore_init(&jool_family);
	return 0;
}

int nlhandler_init(void)
{
	return register_family();
}

void nlhandler_destroy(void)
{
	genl_unregister_family(&jool_family);
}
