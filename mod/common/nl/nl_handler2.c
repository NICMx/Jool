#include "nat64/mod/common/nl/nl_handler.h"

#include <linux/mutex.h>
#include <net/genetlink.h>
#include "nat64/common/genetlink.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/namespace.h"
#include "nat64/mod/common/nl/bib.h"
#include "nat64/mod/common/nl/eam.h"
#include "nat64/mod/common/nl/global.h"
#include "nat64/mod/common/nl/joold.h"
#include "nat64/mod/common/nl/logtime.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/nl/pool.h"
#include "nat64/mod/common/nl/pool4.h"
#include "nat64/mod/common/nl/pool6.h"
#include "nat64/mod/common/nl/session.h"

/* TODO remove? */
static DEFINE_MUTEX(config_mutex);

static int validate_version(struct request_hdr *hdr)
{
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto magic_fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto magic_fail;

	switch (hdr->type) {
	case 's':
		if (xlat_is_nat64()) {
			log_err("You're speaking to NAT64 Jool using the SIIT app.");
			return -EINVAL;
		}
		break;
	case 'n':
		if (xlat_is_siit()) {
			log_err("You're speaking to SIIT Jool using the NAT64 app.");
			return -EINVAL;
		}
		break;
	default:
		goto magic_fail;
	}

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

magic_fail:
	log_err("It appears you're trying to speak to Jool using some other\n"
			"Netlink client or an older userspace application.\n"
			"If the latter is true, please update the userspace app.");
	return -EINVAL;
}

static int multiplex_request(struct xlator *jool, struct request_hdr *jool_hdr,
		struct genl_info *info)
{
	switch (jool_hdr->mode) {
	case MODE_POOL6:
		return handle_pool6_config(jool, info);
	case MODE_POOL4:
		return handle_pool4_config(jool, info);
	case MODE_BIB:
		return handle_bib_config(jool, info);
	case MODE_SESSION:
		/* TODO you sure this isn't undefined behaviour in SIIT? */
		return handle_session_config(jool->nat64.session, info);
	case MODE_EAMT:
		return handle_eamt_config(jool->siit.eamt, info);
	case MODE_RFC6791:
		return handle_addr4pool_config(jool->siit.pool6791, MODE_RFC6791, info);
	case MODE_BLACKLIST:
		return handle_addr4pool_config(jool->siit.blacklist, MODE_BLACKLIST, info);
	case MODE_LOGTIME:
		return handle_logtime_config(info);
	case MODE_GLOBAL:
		return handle_global_config(jool, info);
	case MODE_PARSE_FILE:
		/* TODO */
//		return handle_json_file_config(info);
		break;
	case MODE_JOOLD:
		return handle_joold_request(jool, info);
	}

	log_err("Unknown configuration mode: %d", jool_hdr->mode);
	return nl_core_respond_error(info, 0, -EINVAL);
}

static int handle_jool_message(struct sk_buff *skb_in, struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);
	struct xlator translator;
	int error;

	error = validate_version(jool_hdr);
	if (error)
		/* TODO JOOL_COMMAND is not a config_mode.  */
		return nl_core_respond_error(info, JOOL_COMMAND, error);

	error = joolns_get_current(&translator);
	if (error) {
		if (error == -ESRCH)
			log_err("This namespace lacks a Jool instance.");
		else
			log_err("Unknown error (%d) while trying to retrieve the current namespace.", error);
		return nl_core_respond_error(info, JOOL_COMMAND, error);
	}

	error = multiplex_request(&translator, jool_hdr, info);
	joolns_put(&translator);
	return error;
}

static int handle_jool_message_wrapper(struct sk_buff *skb,
		struct genl_info *info)
{
	int error;

	mutex_lock(&config_mutex);

	error_pool_activate();
	error = handle_jool_message(skb, info);
	error_pool_deactivate();

	mutex_unlock(&config_mutex);

	return error;
}

int nlhandler_init(void)
{
	nl_core_set_main_callback(handle_jool_message_wrapper);
	return 0;
}

void nlhandler_destroy(void)
{
	/* No code. */
}
