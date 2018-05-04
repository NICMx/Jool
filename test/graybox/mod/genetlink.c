#include "genetlink.h"

#include <linux/version.h>
#include "types.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/error_pool.h"

#ifndef GENLMSG_DEFAULT_SIZE
/* This happens in old kernels. */
#define GENLMSG_DEFAULT_SIZE (NLMSG_DEFAULT_SIZE - GENL_HDRLEN)
#endif

/**
 * See nl_core#NLBUFFER_MAX_PAYLOAD.
 */
#define NLBUFFER_MAX_PAYLOAD ((size_t)(GENLMSG_DEFAULT_SIZE - 256))

static struct genl_family *family;

void genl_setup(struct genl_family *new_family)
{
	family = new_family;
}

static int respond(struct genl_info *info, int error_code,
		int attr_id, void *attr, size_t attr_len)
{
	struct sk_buff *skb;
	size_t total_size;
	void *msg_head;
	int error;
	uint32_t pid;

	total_size = nla_total_size(sizeof(__u16)) + nla_total_size(attr_len);

	skb = genlmsg_new(total_size, GFP_KERNEL);
	if (!skb) {
		pr_err("genlmsg_new() failed.\n");
		return -ENOMEM;
	}
#if LINUX_VERSION_LOWER_THAN(3, 7, 0, 7, 0)
	pid = info->snd_pid;
#else
	pid = info->snd_portid;
#endif

	msg_head = genlmsg_put(skb, pid, info->nlhdr->nlmsg_seq, family, 0, 0);
	if (!msg_head) {
		pr_err("genlmsg_put() failed.\n");
		kfree_skb(skb);
		return -ENOMEM;
	}

	error = nla_put_u16(skb, ATTR_ERROR_CODE, abs(error_code));
	if (error) {
		pr_err("nla_put_u16() failed. (errcode %d)\n", error);
		kfree_skb(skb);
		return error;
	}

	if (attr) {
		error = nla_put(skb, attr_id, attr_len, attr);
		if (error) {
			pr_err("nla_put() failed. (errcode %d)\n", error);
			kfree_skb(skb);
			return error;
		}
	}

	genlmsg_end(skb, msg_head);

	error = genlmsg_reply(skb, info); /* Implicit kfree_skb(skb) here. */
	if (error) {
		pr_err("genlmsg_reply() failed. (errcode %d)\n", error);
		return error;
	}

	return 0;
}

int genl_respond(struct genl_info *info, int error_code)
{
	char *error_msg;
	size_t error_msg_size;
	int error;

	error = error_pool_get_message(&error_msg, &error_msg_size);
	if (error)
		return error; /* Error msg already printed. */

	if (error_msg_size > NLBUFFER_MAX_PAYLOAD) {
		error_msg[NLBUFFER_MAX_PAYLOAD - 1] = '\0';
		error_msg_size = NLBUFFER_MAX_PAYLOAD;
	}

	error = respond(info, error_code, ATTR_ERROR_STRING, error_msg,
			error_msg_size);
	if (error_msg)
		kfree(error_msg);

	return error;
}

int genl_respond_attr(struct genl_info *info, int attr_id, void *attr,
		size_t attr_len)
{
	return respond(info, 0, attr_id, attr, attr_len);
}
