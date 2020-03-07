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

//int nlcore_send_multicast_message(struct net *ns, struct nlcore_buffer *buffer)
//{
//	int error;
//	struct sk_buff *skb;
//	void *msg_head;
//
//	skb = genlmsg_new(nla_total_size(buffer->len), GFP_ATOMIC);
//	if (!skb)
//		return -ENOMEM;
//
//	msg_head = genlmsg_put(skb, 0, 0, family, 0, 0);
//	if (!msg_head) {
//		pr_err("genlmsg_put() returned NULL.\n");
//		return -ENOMEM;
//	}
//
//	error = nla_put(skb, ATTR_DATA, buffer->len, buffer->data);
//	if (error) {
//		pr_err("nla_put() failed. (errcode %d)\n", error);
//		kfree_skb(skb);
//		return error;
//	}
//
//	genlmsg_end(skb, msg_head);
//
//#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)
//	error = genlmsg_multicast_netns(ns, skb, 0, group->id, GFP_ATOMIC);
//#else
//	/*
//	 * Note: Starting from kernel 3.13, all groups of a common family share
//	 * a group offset (from a common pool), and they are numbered
//	 * monotonically from there. That means if all we have is one group,
//	 * its id will always be zero.
//	 *
//	 * That's the reason why so many callers of this function stopped
//	 * providing a group when the API started forcing them to provide a
//	 * family.
//	 */
//	error = genlmsg_multicast_netns(family, ns, skb, 0, 0, GFP_ATOMIC);
//#endif
//	if (error) {
//		log_warn_once("Looks like nobody received my multicast message. Is the joold daemon really active? (errcode %d)",
//				error);
//		return error;
//	}
//
//	return 0;
//}
