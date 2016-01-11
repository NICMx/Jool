#include <linux/module.h>
#include <net/genetlink.h>
#include <linux/sort.h>
#include <linux/version.h>
#include "nat64/common/constants.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/namespace.h"

#include "nat64/mod/common/json_parser.h"

#include "nat64/mod/common/error_pool.h"
#include "nat64/mod/common/nl/bib.h"
#include "nat64/mod/common/nl/blacklist.h"
#include "nat64/mod/common/nl/eam.h"
#include "nat64/mod/common/nl/global.h"
#include "nat64/mod/common/nl/joold.h"
#include "nat64/mod/common/nl/logtime.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/pool.h"
#include "nat64/mod/common/nl/pool4.h"
#include "nat64/mod/common/nl/pool6.h"
#include "nat64/mod/common/nl/session.h"


/*#include "nat64/mod/common/nl/nl_receiver.h"*/

static DEFINE_MUTEX(config_mutex);

static int validate_version(struct request_hdr *hdr) {
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto magic_fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto magic_fail;

	switch (hdr->type) {
	case 's':
		if (xlat_is_nat64()) {
			log_err(
					"You're speaking to NAT64 Jool using " "the SIIT Jool application.");
			return -EINVAL;
		}
		break;
	case 'n':
		if (xlat_is_siit()) {
			log_err(
					"You're speaking to SIIT Jool using " "the NAT64 Jool application.");
			return -EINVAL;
		}
		break;
	default:
		goto magic_fail;
	}

	if (xlat_version() == hdr->version)
		return 0;

	log_err(
			"Version mismatch. The kernel module is %u.%u.%u.%u, " "but the userspace application is %u.%u.%u.%u. " "Please update Jool's %s.",
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR, JOOL_VERSION_REV,
			JOOL_VERSION_DEV, hdr->version >> 24, (hdr->version >> 16) & 0xFFU,
			(hdr->version >> 8) & 0xFFU, hdr->version & 0xFFU,
			(xlat_version() > hdr->version) ?
					"userspace application" : "kernel module");
	return -EINVAL;

	magic_fail:
	log_err(
			"It appears you're trying to speak to Jool using some other " "Netlink client or an older userspace application. " "If the latter is true, please update your userspace " "application.");
	return -EINVAL;
}


static int handle_jool_message(struct sk_buff *skb_in,	struct genl_info *info)
{

	struct request_hdr *jool_hdr;
	int error;

	jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);


	error = validate_version(jool_hdr);

	if (error)
		return nl_core_respond_error(info, JOOL_COMMAND, error);

	switch (jool_hdr->mode) {
	case MODE_POOL6:
		return handle_pool6_config(info);
	case MODE_POOL4:
		return handle_pool4_config(info);
	case MODE_BIB:
		return handle_bib_config(info);
	case MODE_SESSION:
		return handle_session_config(info);
	case MODE_EAMT:
		return handle_eamt_config(info);
	case MODE_RFC6791:
		return handle_rfc6791_config(info);
	case MODE_BLACKLIST:
		return handle_blacklist_config(info);
	case MODE_LOGTIME:
		return handle_logtime_config(info);
	case MODE_GLOBAL:
		return handle_global_config(info);
	case MODE_PARSE_FILE:
		return handle_json_file_config(info);
	case MODE_JOOLD:
		return handle_joold_request(info);

	}

	log_err("Unknown configuration mode: %d", jool_hdr->mode);
	return nl_core_respond_error(info, 0, -EINVAL);

}

static int handle_jool_message_wrapper(struct sk_buff *skb_in, struct genl_info *info)
{
	int error = 0;

	mutex_lock(&config_mutex);

	error_pool_activate();
	error = handle_jool_message(skb_in, info);
	error_pool_deactivate();

	mutex_unlock(&config_mutex);

	return error;
}

void nlhandler_init(void) {

	nl_core_set_main_callback(handle_jool_message_wrapper);
}

void nlhandler_destroy(void) {

}
