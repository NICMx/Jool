#include "nat64/mod/common/nl/nl_handler.h"

#include <linux/mutex.h>
#include <net/genetlink.h>
#include "nat64/common/genetlink.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
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

/* TODO (final) remove? */
static DEFINE_MUTEX(config_mutex);

static int validate_magic(struct request_hdr *hdr)
{
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto fail;
	return 0;

fail:
	log_err("It appears you're trying to speak to Jool using some other\n"
			"Netlink client or an older userspace application.\n"
			"If the latter is true, please update the userspace app.");
	return -EINVAL;
}

static int validate_stateness(struct request_hdr *hdr)
{
	switch (hdr->type) {
	case 's':
		if (xlat_is_siit())
			return 0;

		log_err("You're speaking to NAT64 Jool using the SIIT app.");
		return -EINVAL;
	case 'n':
		if (xlat_is_nat64())
			return 0;

		log_err("You're speaking to SIIT Jool using the NAT64 app.");
		return -EINVAL;
	}

	log_err("Unknown stateness: '%c'", hdr->type);
	return -EINVAL;
}

static int validate_version(struct request_hdr *hdr)
{
	if (xlat_version() == hdr->version)
		return 0;

	log_err("Version mismatch. The kernel module is %u.%u.%u.%u,\n"
			"but the userspace application is %u.%u.%u.%u.\n"
			"Please update Jool's %s.",
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV,
			hdr->version >> 24, (hdr->version >> 16) & 0xFFU,
			(hdr->version >> 8) & 0xFFU, hdr->version & 0xFFU,
			(xlat_version() > hdr->version)
					? "userspace application"
					: "kernel module");
	return -EINVAL;
}

static int validate_header(struct genl_info *info)
{
	struct nlattr *attr = info->attrs[ATTR_DATA];
	struct request_hdr *hdr;
	int error;

	if (nla_len(attr) < sizeof(struct request_hdr)) {
		log_err("The message is too small to even contain Jool's header.");
		return -EINVAL;
	}

	hdr = (struct request_hdr *)(attr + 1);

	error = validate_magic(hdr);
	if (error)
		return error;
	error = validate_stateness(hdr);
	if (error)
		return error;
	error = validate_version(hdr);
	if (error)
		return error;

	if (nla_len(attr) != get_jool_hdr(info)->length) {
		log_err("Generic Netlink's packet size does not match the amount the client claims it sent.");
		return -EINVAL;
	}

	return 0;
}

static int multiplex_request(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);

	switch (jool_hdr->mode) {
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

	log_err("Unknown configuration mode: %d", jool_hdr->mode);
	return nlcore_respond_error(info, -EINVAL);
}

static int __handle_jool_message(struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);
	struct xlator translator;
	int error;

	log_debug("===============================================");

	error = validate_header(info);
	if (error)
		return error; /* client is not Jool, so don't answer. */

	if (jool_hdr->mode == MODE_INSTANCE)
		return handle_instance_request(info);

	error = xlator_find_current(&translator);
	if (error == -ESRCH) {
		log_err("This namespace lacks a Jool instance.");
		return nlcore_respond_error(info, -ESRCH);
	}
	if (error) {
		log_err("Unknown error %d; Jool instance not found.", error);
		return nlcore_respond_error(info, error);
	}

	/*
	 * TODO wasn't there something we needed to do to tell genetlink we're
	 * namespace-aware?
	 */

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
