#include "nat64/mod/common/nl/nl_handler.h"

#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/genetlink.h>
#include "nat64/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/atomic_config.h"
#include "nat64/mod/common/nl/bib.h"
#include "nat64/mod/common/nl/eam.h"
#include "nat64/mod/common/nl/global.h"
#include "nat64/mod/common/nl/instance.h"
#include "nat64/mod/common/nl/joold.h"
#include "nat64/mod/common/nl/logtime.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/nl/pool.h"
#include "nat64/mod/common/nl/pool4.h"
#include "nat64/mod/common/nl/pool6.h"
#include "nat64/mod/common/nl/session.h"

static struct genl_multicast_group mc_groups[1] = {
	{
		.name = GNL_JOOLD_MULTICAST_GRP_NAME,
#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)
		.id = JOOLD_MC_ID,
#endif
	},
};

/**
 * Actual message type definition.
 */
static struct genl_ops ops[] = {
	{
		.cmd = JOOL_COMMAND,
		.doit = handle_jool_message,
		.dumpit = NULL,
	},
};

static struct genl_family jool_family = {
#if LINUX_VERSION_LOWER_THAN(4, 10, 0, 9999, 0)
	/* This variable became "private" on kernel 4.10. */
	.id = GENL_ID_GENERATE,
#endif
	.hdrsize = 0,
	/* This is initialized below. See register_family(). */
	/* .name = GNL_JOOL_FAMILY_NAME, */
	.version = 1,
	.maxattr = __ATTR_MAX,
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
	/*
	 * "pre_doit" and "post_doit" are a pain in the ass; there is no doit
	 * function so I have no idea. Whatever; they can be null. Fuck 'em.
	 */

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

static DEFINE_MUTEX(config_mutex);

static int multiplex_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	switch (be16_to_cpu(hdr->mode)) {
	case MODE_POOL6:
		return handle_pool6_config(jool, info);
	case MODE_POOL4:
		return handle_pool4_config(jool, info);
	case MODE_BIB:
		return handle_bib_config(jool, info);
	case MODE_SESSION:
		return handle_session_config(jool, info);
	case MODE_EAMT:
		return handle_eamt_config(jool, info);
	case MODE_RFC6791:
		return handle_pool6791_config(jool, info);
	case MODE_BLACKLIST:
		return handle_blacklist_config(jool, info);
	case MODE_LOGTIME:
		return handle_logtime_config(info);
	case MODE_GLOBAL:
		return handle_global_config(jool, info);
	case MODE_PARSE_FILE:
		return handle_atomconfig_request(jool, info);
	case MODE_JOOLD:
		return handle_joold_request(jool, info);
	case MODE_INSTANCE:
		return handle_instance_request(info);
	}

	log_err("Unknown configuration mode: %d", be16_to_cpu(hdr->mode));
	return nlcore_respond(info, -EINVAL);
}

static int __handle_jool_message(struct genl_info *info)
{
	struct xlator translator;
	bool client_is_jool;
	int error;

	log_debug("===============================================");
	log_debug("Received a request from userspace.");

	error = validate_request(nla_data(info->attrs[ATTR_DATA]),
			nla_len(info->attrs[ATTR_DATA]),
			"userspace client",
			"kernel module",
			&client_is_jool);
	if (error)
		return client_is_jool ? nlcore_respond(info, error) : error;

	if (be16_to_cpu(get_jool_hdr(info)->mode) == MODE_INSTANCE)
		return handle_instance_request(info);

	error = xlator_find_current(&translator);
	if (error == -ESRCH) {
		log_err("This namespace lacks a Jool instance.");
		return nlcore_respond(info, -ESRCH);
	}
	if (error) {
		log_err("Unknown error %d; Jool instance not found.", error);
		return nlcore_respond(info, error);
	}

	error = multiplex_request(&translator, info);
	xlator_put(&translator);
	return error;
}

int handle_jool_message(struct sk_buff *skb, struct genl_info *info)
{
	int error;

	mutex_lock(&config_mutex);

	error_pool_activate();
	error = __handle_jool_message(info);
	error_pool_deactivate();

	mutex_unlock(&config_mutex);

	return error;
}

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

	nlcore_init(&jool_family, &mc_groups[0]);
	return 0;
}

int nlhandler_init(void)
{
	error_pool_init();
	return register_family();
}

void nlhandler_destroy(void)
{
	genl_unregister_family(&jool_family);
	error_pool_destroy();
}
