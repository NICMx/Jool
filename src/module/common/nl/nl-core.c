#include "nat64/mod/common/nl/nl_core2.h"

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>
#include "nat64/common/config.h"
#include "nat64/common/types.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/common/nl/nl_common.h"

/*
 * Note: If you're working on this module, please keep in mind that there should
 * not be any log_err()s anywhere.
 *
 * If a preparation to send something to userspace failed, then trying to send
 * the error message (via log_err()) to userspace is a fairly lost cause.
 */

#ifndef GENLMSG_DEFAULT_SIZE
/* This happens in old kernels. */
#define GENLMSG_DEFAULT_SIZE (NLMSG_DEFAULT_SIZE - GENL_HDRLEN)
#endif

/*
 * From my experience, the maximum packet size is exactly PAGE_SIZE. Any more
 * and the packet will not be delivered. (and the packet dispatch function will
 * return success, go figure.)
 *
 * But we don't care about that; what we need is the maximum available payload
 * size. There are lots and potentially quirky headers involved (Netlink,
 * Generic netlink and attributes), so it is difficult to predict.
 *
 * Kernel users typically use GENLMSG_DEFAULT_SIZE when allocating packets that
 * will hold attributes in Generic Netlink messages. I don't understand the
 * rationale; there can be any number of attributes, and each will need a
 * header, so predicting payload room using a constant seems asinine to me.
 *
 * Thankfully, we only have one attribute, so if the logic is wrong they should
 * crash long before us. Ha!
 *
 * In any case, GENLMSG_DEFAULT_SIZE is 3756 in the 4096-PAGE_SIZE machine I'm
 * coding on, so at least there's plenty of room for error it seems.
 *
 * The 256 is fairly arbitrary. GENLMSG_DEFAULT_SIZE is meant to compensate for
 * [G]Netlink headers (I guess), and I want additional insurance to compensate
 * for any buffer-to-packet eventualities. I do not think it is useful right
 * now, but (considering a silent packet drop is perceived as a success) I do
 * not want to tempt the devil.
 *
 * IF YOU PLAN ON TWEAKING THIS MACRO, YOU HAVE TO CASCADE YOUR CHANGES TO THE
 * BUILD_BUG_ON() AT nlcore_init()!!!
 */
#define NLBUFFER_MAX_PAYLOAD ((size_t)(GENLMSG_DEFAULT_SIZE - 256))

static struct genl_family *family;
static struct genl_multicast_group *group;

void nlcore_init(struct genl_family *new_family,
		struct genl_multicast_group *new_group)
{
	/*
	 * If this triggers, GENLMSG_DEFAULT_SIZE is too small.
	 * Sorry; I don't want to use BUILD_BUG_ON_MSG because old kernels don't
	 * have it.
	 */
	BUILD_BUG_ON(GENLMSG_DEFAULT_SIZE <= 256);

	family = new_family;
	group = new_group;
}

static int respond_single_msg(struct genl_info *info, struct nlcore_buffer *buffer)
{
	struct sk_buff *skb;
	void *msg_head;
	int error;
	uint32_t portid;

	skb = genlmsg_new(nla_total_size(buffer->len), GFP_KERNEL);
	if (!skb) {
		pr_err("genlmsg_new() failed.\n");
		return -ENOMEM;
	}
#if LINUX_VERSION_LOWER_THAN(3, 7, 0, 7, 0)
	portid = info->snd_pid;
#else
	portid = info->snd_portid;
#endif

	msg_head = genlmsg_put(skb, portid, info->nlhdr->nlmsg_seq, family, 0,
			be16_to_cpu(get_jool_hdr(info)->mode));
	if (!msg_head) {
		pr_err("genlmsg_put() failed.\n");
		kfree_skb(skb);
		return -ENOMEM;
	}

	error = nla_put(skb, ATTR_DATA, buffer->len, buffer->data);
	if (error) {
		pr_err("nla_put() failed. (errcode %d)\n", error);
		kfree_skb(skb);
		return error;
	}

	genlmsg_end(skb, msg_head);

	error = genlmsg_reply(skb, info);
	if (error) {
		pr_err("genlmsg_reply() failed. (errcode %d)\n", error);
		return error;
	}

	return 0;
}

size_t nlbuffer_response_max_size(void)
{
	return NLBUFFER_MAX_PAYLOAD - sizeof(struct response_hdr);
}

static int __nlbuffer_init(struct nlcore_buffer *buffer, size_t capacity)
{
	if (WARN(capacity > NLBUFFER_MAX_PAYLOAD,
			"Message size is too big. (%zu > %zu)",
			capacity, NLBUFFER_MAX_PAYLOAD))
		return -EINVAL;

	buffer->len = 0;
	buffer->capacity = capacity;
	buffer->data = __wkmalloc("nlcore_buffer.data", capacity, GFP_ATOMIC);
	return buffer->data ? 0 : -ENOMEM;
}

int nlbuffer_init_request(struct nlcore_buffer *buffer, struct request_hdr *hdr,
		size_t capacity)
{
	int error;

	error = __nlbuffer_init(buffer, sizeof(*hdr) + capacity);
	if (error)
		return error;

	return nlbuffer_write(buffer, hdr, sizeof(*hdr));
}

int nlbuffer_init_response(struct nlcore_buffer *buffer, struct genl_info *info,
		size_t capacity)
{
	struct response_hdr response;
	int error;

	error = __nlbuffer_init(buffer, sizeof(response) + capacity);
	if (error)
		return error;

	memcpy(&response.req, get_jool_hdr(info), sizeof(response.req));
	response.req.castness = 'u';
	response.error_code = 0;
	response.pending_data = false;
	return nlbuffer_write(buffer, &response, sizeof(response));
}

void nlbuffer_free(struct nlcore_buffer *buffer)
{
	__wkfree("nlcore_buffer.data", buffer->data);
}

int nlbuffer_write(struct nlcore_buffer *buffer, void *data, size_t data_size)
{
	if (buffer->len + data_size > buffer->capacity) {
		log_debug("The buffer's storage capacity has been surpassed.");
		/*
		 * Do not set the pending data flag yet; not everyone wants it.
		 */
		return 1;
	}

	memcpy(buffer->data + buffer->len, data, data_size);
	buffer->len += data_size;
	return 0;
}

int nlbuffer_send(struct genl_info *info, struct nlcore_buffer *buffer)
{
	if (buffer->len > NLBUFFER_MAX_PAYLOAD) {
		pr_err("The response is too long; cannot send to userspace.\n");
		return -EINVAL;
	}

	return respond_single_msg(info, buffer);
}

void nlbuffer_set_pending_data(struct nlcore_buffer *buffer, bool pending_data)
{
	struct response_hdr *hdr = buffer->data;
	hdr->pending_data = pending_data;
}

void nlbuffer_set_errcode(struct nlcore_buffer *buffer, int error)
{
	struct response_hdr *hdr = buffer->data;
	error = abs(error);
	hdr->error_code = (error > 0xFFFFu) ? 0xFFFFu : error;
}

static int respond_error(struct genl_info *info, int error_code)
{
	struct nlcore_buffer buffer;
	int error;
	char *error_msg;
	size_t error_msg_size;

	error = error_pool_get_message(&error_msg, &error_msg_size);
	if (error)
		return error; /* Error msg already printed. */

	if (error_msg_size > NLBUFFER_MAX_PAYLOAD) {
		error_msg[NLBUFFER_MAX_PAYLOAD - 1] = '\0';
		error_msg_size = NLBUFFER_MAX_PAYLOAD;
	}

	error = nlbuffer_init_response(&buffer, info, error_msg_size);
	if (error) {
		pr_err("Errcode %d while initializing a response to userspace.\n",
				error);
		goto end_simple;
	}

	nlbuffer_set_errcode(&buffer, error_code);

	error = nlbuffer_write(&buffer, error_msg, error_msg_size);
	if (error) {
		pr_err("Errcode %d while writing on a response to userspace.\n",
				error);
		goto end_full;
	}

	if (error_code)
		log_debug("Sending error code %d to userspace.", error_code);
	else
		log_debug("Sending ACK to userspace.");
	error = respond_single_msg(info, &buffer);
	/* Fall through. */

end_full:
	nlbuffer_free(&buffer);
end_simple:
	__wkfree("Error msg out", error_msg);
	return error;
}

static int respond_ack(struct genl_info *info)
{
	int error;
	struct nlcore_buffer buffer;

	error = nlbuffer_init_response(&buffer, info, 0);
	if (error) {
		pr_err("Errcode %d while initializing a response to userspace.\n",
				error);
		return error;
	}

	error = respond_single_msg(info, &buffer);

	nlbuffer_free(&buffer);
	return error;
}


int nlcore_respond(struct genl_info *info, int error)
{
	return error ? respond_error(info, error) : respond_ack(info);
}

int nlcore_respond_struct(struct genl_info *info, void *content,
		size_t content_len)
{
	struct nlcore_buffer buffer;
	int error;

	error = nlbuffer_init_response(&buffer, info, content_len);
	if (error) {
		pr_err("Errcode %d while initializing a response to userspace.\n",
				error);
		return respond_error(info, error);
	}

	error = nlbuffer_write(&buffer, content, content_len);
	if (error < 0) {
		pr_err("Errcode %d while writing on a response to userspace.\n",
				error);
		return respond_error(info, error);
	}
	/*
	 * @content is supposed to be a statically-defined struct, and as such
	 * should be several orders smaller than the Netlink packet size limit.
	 */
	if (WARN(error > 0, "Content exceeds the maximum packet size."))
		return respond_error(info, -E2BIG);

	error = nlbuffer_send(info, &buffer);
	nlbuffer_free(&buffer);
	return error;
}

int nlcore_send_multicast_message(struct net *ns, struct nlcore_buffer *buffer)
{
	int error;
	struct sk_buff *skb;
	void *msg_head;

	skb = genlmsg_new(nla_total_size(buffer->len), GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	msg_head = genlmsg_put(skb, 0, 0, family, 0, 0);
	if (!msg_head) {
		pr_err("genlmsg_put() returned NULL.\n");
		return -ENOMEM;
	}

	error = nla_put(skb, ATTR_DATA, buffer->len, buffer->data);
	if (error) {
		pr_err("nla_put() failed. (errcode %d)\n", error);
		kfree_skb(skb);
		return error;
	}

	genlmsg_end(skb, msg_head);

#if LINUX_VERSION_LOWER_THAN(3, 13, 0, 7, 1)
	error = genlmsg_multicast_netns(ns, skb, 0, group->id, GFP_ATOMIC);
#else
	/*
	 * Note: Starting from kernel 3.13, all groups of a common family share
	 * a group offset (from a common pool), and they are numbered
	 * monotonically from there. That means if all we have is one group,
	 * its id will always be zero.
	 *
	 * That's the reason why so many callers of this function stopped
	 * providing a group when the API started forcing them to provide a
	 * family.
	 */
	error = genlmsg_multicast_netns(family, ns, skb, 0, 0, GFP_ATOMIC);
#endif
	if (error) {
		log_warn_once("Looks like nobody received my multicast message. Is the joold daemon really active? (errcode %d)",
				error);
		return error;
	}

	return 0;
}
