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

static struct genl_multicast_group mc_groups[1] = {
	{ .name = GNL_JOOLD_MULTICAST_GRP_NAME, },
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
#if LINUX_VERSION_LOWER_THAN(4, 10, 0, 7, 5)
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

static DEFINE_MUTEX(config_mutex);

static int validate_magic(struct request_hdr *hdr)
{
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto fail;
	return 0;

fail:
	/* Well, the sender does not understand the protocol. */
	log_err("The userspace client's request lacks the Jool magic text.");
	return -EINVAL;
}

static int validate_stateness(struct request_hdr *hdr)
{
	switch (hdr->xt) {
	case XT_SIIT:
		if (is_siit_enabled())
			return 0;
		log_err("SIIT Jool has not been modprobed. (Try `modprobe jool_siit`)");
		return -EINVAL;
	case XT_NAT64:
		if (is_nat64_enabled())
			return 0;
		log_err("NAT64 Jool has not been modprobed. (Try `modprobe jool`)");
		return -EINVAL;
	}

	log_err(XT_VALIDATE_ERRMSG);
	return -EINVAL;
}

static int validate_version(struct request_hdr *hdr)
{
	__u32 hdr_version = ntohl(hdr->version);

	if (xlat_version() == hdr_version)
		return 0;

	log_err("Version mismatch. The userspace client's version is %u.%u.%u.%u,\n"
			"but the kernel module is %u.%u.%u.%u.\n"
			"Please update the %s.",
			hdr_version >> 24, (hdr_version >> 16) & 0xFFU,
			(hdr_version >> 8) & 0xFFU, hdr_version & 0xFFU,
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV,
			(xlat_version() > hdr_version)
					? "userspace client"
					: "kernel module");
	return -EINVAL;
}

static int validate_request(void *data, size_t data_len, bool *peer_is_jool)
{
	int error;

	if (peer_is_jool)
		*peer_is_jool = false;

	if (data_len < sizeof(struct request_hdr)) {
		log_err("Message from the userspace client is smaller than Jool's header.");
		return -EINVAL;
	}

	error = validate_magic(data);
	if (error)
		return error;

	if (peer_is_jool)
		*peer_is_jool = true;

	error = validate_stateness(data);
	if (error)
		return error;
	return validate_version(data);
}


static int validate_genl_attrs(struct genl_info *info)
{
	/*
	 * I smell a need for another genl refactor.
	 * Damn it, this thing is so hard to nail right.
	 */
	if (info->attrs == NULL || info->attrs[ATTR_DATA] == NULL) {
		log_err("Malformed request. Most likely, the client is not Jool, or its version is pre-4.0. I can't even respond. Sorry.");
		return -EINVAL;
	}

	return 0;
}

static int multiplex_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	switch (hdr->mode) {
	case MODE_ADDRESS:
		return handle_address_query(jool, info);
	case MODE_STATS:
		return handle_stats_config(jool, info);
	case MODE_GLOBAL:
		return handle_global_config(jool, info);
	case MODE_EAMT:
		return handle_eamt_config(jool, info);
	case MODE_BLACKLIST:
		return handle_blacklist4_config(jool, info);
	case MODE_POOL4:
		return handle_pool4_config(jool, info);
	case MODE_BIB:
		return handle_bib_config(jool, info);
	case MODE_SESSION:
		return handle_session_config(jool, info);
	case MODE_JOOLD:
		return handle_joold_request(jool, info);
	default:
		log_err("Unknown configuration mode: %d", hdr->mode);
		return nlcore_respond(info, -EINVAL);
	}
}

static int __handle_jool_message(struct genl_info *info)
{
	struct request_hdr *hdr;
	struct xlator jool;
	bool client_is_jool;
	int error;

	error = validate_genl_attrs(info);
	if (error)
		return error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("===============================================");
	log_debug("Received a request from userspace.");

	error = validate_request(nla_data(info->attrs[ATTR_DATA]),
			nla_len(info->attrs[ATTR_DATA]),
			&client_is_jool);
	if (error)
		return client_is_jool ? nlcore_respond(info, error) : error;

	hdr = get_jool_hdr(info);
	switch (hdr->mode) {
	case MODE_INSTANCE:
		return handle_instance_request(info);
	case MODE_PARSE_FILE:
		return handle_atomconfig_request(info);
	default:
		break;
	}

	error = xlator_find_current(get_iname(info), XF_ANY | hdr->xt, &jool);
	if (error == -ESRCH) {
		log_err("This namespace lacks an instance named '%s'.",
				get_iname(info));
		return nlcore_respond(info, -ESRCH);
	}
	if (error)
		return nlcore_respond(info, error);

	error = multiplex_request(&jool, info);
	xlator_put(&jool);
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

	strcpy(jool_family.name, GNL_JOOL_FAMILY);

#if LINUX_VERSION_LOWER_THAN(4, 10, 0, 7, 5)
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
