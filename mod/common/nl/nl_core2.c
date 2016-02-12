#include "nat64/mod/common/nl/nl_core2.h"

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>
#include "nat64/common/config.h"
#include "nat64/common/genetlink.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_handler.h"

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
#define NLBUFFER_MAX_PAYLOAD \
	(GENLMSG_DEFAULT_SIZE - sizeof(struct response_hdr) - 256)

static struct genl_multicast_group mc_groups[1] = {
	{
		.name = GNL_JOOLD_MULTICAST_GRP_NAME,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
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
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = GNL_JOOL_FAMILY_NAME,
	.version = 1,
	.maxattr = __ATTR_MAX,
};

size_t nlbuffer_size(struct nlcore_buffer *buffer)
{
	return sizeof(struct response_hdr) + buffer->payload_len;
}

static int respond_single_msg(struct genl_info *info, struct nlcore_buffer *buffer)
{
	struct sk_buff *skb;
	void *msg_head;
	int error;
	uint32_t portid;

	skb = genlmsg_new(nla_total_size(nlbuffer_size(buffer)), GFP_KERNEL);
	if (!skb) {
		pr_err("genlmsg_new() failed.\n");
		return -ENOMEM;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	portid = info->snd_pid;
#else
	portid = info->snd_portid;
#endif

	msg_head = genlmsg_put(skb, portid, 0, &jool_family, 0,
			get_jool_hdr(info)->mode);
	if (!msg_head) {
		pr_err("genlmsg_put() failed.\n");
		kfree_skb(skb);
		return -ENOMEM;
	}

	error = nla_put(skb, ATTR_DATA, nlbuffer_size(buffer), buffer->data);
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

size_t nlbuffer_data_max_size(void)
{
	return NLBUFFER_MAX_PAYLOAD;
}

/**
 * Caller writes on the buffer. Once the buffer is full or the caller finishes
 * writing, the buffer is written into an skb and fetched.
 *
 * The caller does not work on the skb directly because:
 *
 * Rob had trouble making Generic Netlink work without attributes. It might be
 * impossible. We do not want to fetch attributes because we do not have any
 * warranty they will work the same in a different Linux kernel (which is
 * relevant in joold's case - the two NAT64s can be running in different
 * kernels). So what we did is use a single binary attribute. Userspace joold
 * unwraps the attribute and sends the binary data as is. The joold on the other
 * side should parse the data correctly because it is reasonable to expect
 * Jool's version to be the same.
 *
 * TODO did we include the magic number and module version in that message?
 *
 * The problem with that is the binary blob needs to be ready by the time the
 * attribute is written into the packet. This is never the case for responses
 * to --display. In fact, it is also not true for joold.
 *
 * So we use a buffer to build the attribute content first and write the
 * attribute later.
 *
 * TODO (later) maybe find a way to do this without attributes?
 */
int nlbuffer_init(struct nlcore_buffer *buffer, struct genl_info *info,
		size_t capacity)
{
	struct request_hdr *request = get_jool_hdr(info);
	struct response_hdr *response;

	if (WARN(capacity > NLBUFFER_MAX_PAYLOAD, "Message size is too big.")) {
		log_err("Message size is too big. (%zu > %zu)", capacity,
				(size_t)NLBUFFER_MAX_PAYLOAD);
		return -EINVAL;
	}

	buffer->payload_len = 0;
	buffer->capacity = capacity;
	buffer->data = kmalloc(sizeof(struct response_hdr) + capacity, GFP_ATOMIC);
	if (!buffer->data) {
		log_err("Could not allocate memory for nl_core_buffer!");
		return -ENOMEM;
	}

	response = buffer->data;
	memcpy(&response->req, request, sizeof(*request));
	response->error_code = 0;
	response->pending_data = false;

	return 0;
}

void nlbuffer_free(struct nlcore_buffer *buffer)
{
	kfree(buffer->data);
}

bool nlbuffer_write(struct nlcore_buffer *buffer, void *data, size_t data_size)
{
	void *tail;

	if (buffer->payload_len + data_size > buffer->capacity) {
		log_debug("The buffer's storage capacity has been surpassed.");
		nlbuffer_set_pending_data(buffer, true);
		return 1;
	}

	tail = buffer->data + sizeof(struct response_hdr) + buffer->payload_len;
	memcpy(tail, data, data_size);
	buffer->payload_len += data_size;

	return 0;
}

int nlcore_send_multicast_message(struct nlcore_buffer *buffer)
{
	int error;
	struct sk_buff *skb;
	void *msg_head;

	skb = genlmsg_new(nla_total_size(nlbuffer_size(buffer)), GFP_ATOMIC);
	if (!skb) {
		log_debug("Failed to allocate the multicast message.");
		return -ENOMEM;
	}

	msg_head = genlmsg_put(skb, 0, 0, &jool_family, 0, 0);
	if (msg_head) {
		log_err("genlmsg_put() returned NULL.");
		return -ENOMEM;
	}

	error = nla_put(skb, ATTR_DATA, nlbuffer_size(buffer), buffer->data);
	if (error) {
		pr_err("nla_put() failed. (errcode %d)\n", error);
		kfree_skb(skb);
		return error;
	}

	genlmsg_end(skb, msg_head);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	error = genlmsg_multicast_allns(skb, 0, mc_groups[0].id, 0);
#else
	error = genlmsg_multicast_allns(&jool_family, skb, 0, 0, GFP_ATOMIC);
#endif
	if (error) {
		log_warn_once("Sending multicast message failed. (errcode %d)",
				error);
		return error;
	}

	return 0;
}

int nlbuffer_send(struct genl_info *info, struct nlcore_buffer *buffer)
{
	if (buffer->payload_len > NLBUFFER_MAX_PAYLOAD) {
		log_err("Buffer too long to be sent!");
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

int nlcore_respond_error(struct genl_info *info, int error_code)
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

	error = nlbuffer_init(&buffer, info, error_msg_size);
	if (error) {
		pr_err("Error while trying to allocate buffer for sending error message!\n");
		goto end_simple;
	}

	nlbuffer_set_errcode(&buffer, error_code);

	error = nlbuffer_write(&buffer, error_msg, error_msg_size);
	if (error) {
		pr_err("Error while trying to write to buffer for sending error message!\n");
		goto end_full;
	}

	error = respond_single_msg(info, &buffer);
	/* Fall through. */

end_full:
	nlbuffer_free(&buffer);
end_simple:
	kfree(error_msg);
	return error;
}

int nlcore_send_ack(struct genl_info *info)
{
	int error;
	struct nlcore_buffer buffer;

	error = nlbuffer_init(&buffer, info, 0);
	if (error) {
		log_err("Error while trying to allocate buffer for sending acknowledgement!");
		return error;
	}

	error = respond_single_msg(info, &buffer);

	nlbuffer_free(&buffer);
	return error;
}


int nlcore_respond(struct genl_info *info, int error)
{
	if (error)
		return nlcore_respond_error(info, error);
	else
		return nlcore_send_ack(info);
}

int nlcore_respond_struct(struct genl_info *info, void *content,
		size_t content_len)
{
	struct nlcore_buffer buffer;
	int error;

	error = nlbuffer_init(&buffer, info, content_len);
	if (error)
		return nlcore_respond_error(info, error);

	error = nlbuffer_write(&buffer, content, content_len);
	if (error < 0)
		return nlcore_respond_error(info, error);
	/*
	 * @content is supposed to be a statically-defined struct, and as such
	 * should be several orders smaller than the Netlink packet size limit.
	 */
	if (WARN(error > 0, "Content exceeds the maximum packet size."))
		return nlcore_respond_error(info, -E2BIG);

	error = nlbuffer_send(info, &buffer);
	nlbuffer_free(&buffer);
	return error;
}


static int register_family(void)
{
	int error;

	log_debug("Registering Generic Netlink family...");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)

	error = genl_register_family_with_ops(&jool_family, ops, 1);
	if (error) {
		log_err("Couldn't register family!");
		return error;
	}

	error = genl_register_mc_group(&jool_family, &(mc_groups[0]));
	if (error) {
		log_err("Couldn't register multicast group!");
		return error;
	}

#else
	error = genl_register_family_with_ops_groups(&jool_family, ops, mc_groups);
	if (error) {
		log_err("Family registration failed: %d", error);
		return error;
	}
#endif

	return 0;
}

int nlcore_init(void)
{
	/*
	 * If this triggers, GENLMSG_DEFAULT_SIZE is too small.
	 * Sorry; I don't want to use BUILD_BUG_ON_MSG because old kernels don't
	 * have it.
	 */
	BUILD_BUG_ON(GENLMSG_DEFAULT_SIZE <= sizeof(struct response_hdr) + 256);

	error_pool_init();
	return register_family();
}

void nlcore_destroy(void)
{
	genl_unregister_family(&jool_family);
	error_pool_destroy();
}
