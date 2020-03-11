#include "mod/common/nl/nl_core.h"

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>

#include "common/config.h"
#include "common/types.h"
#include "mod/common/error_pool.h"
#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/wkmalloc.h"
#include "mod/common/nl/nl_common.h"

/*
 * Note: If you're working on this module, please keep in mind that there should
 * not be any log_err()s anywhere.
 *
 * If a preparation to send something to userspace failed, then trying to send
 * the error message (via log_err()) to userspace is a fairly lost cause.
 */

static struct genl_family *family;
static struct genl_multicast_group *group;

void nlcore_setup(struct genl_family *new_family,
		struct genl_multicast_group *new_group)
{
	family = new_family;
	group = new_group;
}

struct genl_family *nlcore_get_family(void)
{
	return family;
}

int jresponse_init(struct jool_response *response, struct genl_info *info)
{
	response->info = info;
	response->skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!response->skb) {
		pr_err("genlmsg_new() failed.\n");
		return -ENOMEM;
	}

	response->hdr = genlmsg_put(response->skb, info->snd_portid,
			info->nlhdr->nlmsg_seq, family, 0, 0);
	if (!response->hdr) {
		pr_err("genlmsg_put() failed.\n");
		kfree_skb(response->skb);
		return -ENOMEM;
	}

	memcpy(response->hdr, get_jool_hdr(info), sizeof(*response->hdr));
	return 0;
}

/* Swallows @response. */
int jresponse_send(struct jool_response *response)
{
	int error;

	genlmsg_end(response->skb, response->hdr);

	error = genlmsg_reply(response->skb, response->info);
	if (error)
		pr_err("genlmsg_reply() failed. (errcode %d)\n", error);

	response->skb = NULL;
	return error;
}

void jresponse_cleanup(struct jool_response *response)
{
	kfree_skb(response->skb);
	response->skb = NULL;
}

void jresponse_enable_m(struct jool_response *response)
{
	response->hdr->flags |= HDRFLAGS_M;
}

int jresponse_send_array(struct jool_response *response, int error)
{
	if (error < 0)
		return error;
	/* TODO check at least one entry was written? */
	if (error > 0)
		jresponse_enable_m(response);

	return jresponse_send(response);
}

int jresponse_send_simple(struct genl_info *info, int error_code)
{
	struct jool_response response;
	int error;
	char *error_msg;
	size_t error_msg_size;

	if (error_code < 0)
		error_code = abs(error_code);
	else if (error_code > MAX_U16)
		error_code = MAX_U16;

	error = error_pool_get_message(&error_msg, &error_msg_size);
	if (error)
		return error; /* Error msg already printed. */

	error = jresponse_init(&response, info);
	if (error)
		goto revert_msg;

	if (error_code) {
		response.hdr->flags |= HDRFLAGS_ERROR;

		error = nla_put_u16(response.skb, ERRA_CODE, error_code);
		if (error)
			goto revert_response;

		error = nla_put_string(response.skb, ERRA_MSG, error_msg);
		if (error) {
			error_msg[128] = '\0';
			error = nla_put_string(response.skb, ERRA_MSG, error_msg);
			if (error)
				goto revert_response;
		}
		log_debug("Sending error code %d to userspace.", error_code);
	} else {
		log_debug("Sending ACK to userspace.");
	}

	error = jresponse_send(&response);
	/* Fall through. */

revert_response:
	jresponse_cleanup(&response);
revert_msg:
	__wkfree("Error msg out", error_msg);
	return error;
}

