#include "nl/nl-buffer.h"

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
 * Thankfully, we only have two attributes, so if the logic is wrong they should
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
 * BUILD_BUG_ON() AT jnlbuffer_init()!!!
 */
#define JNLBUFFER_MAX_PAYLOAD ((size_t)(GENLMSG_DEFAULT_SIZE - 256))
#define JNLBUFFER_MAX_SIZE (JNLBUFFER_MAX_PAYLOAD - sizeof(struct response_hdr))

int jnlbuffer_init(struct jnl_buffer *buffer, struct genl_info *info,
		size_t capacity)
{
	struct response_hdr response;
	int error;

	/*
	 * If this triggers, GENLMSG_DEFAULT_SIZE is too small.
	 * Sorry; I don't want to use BUILD_BUG_ON_MSG because old kernels don't
	 * have it.
	 */
	BUILD_BUG_ON(GENLMSG_DEFAULT_SIZE <= 256);

	capacity += sizeof(response);

	if (WARN(capacity > JNLBUFFER_MAX_PAYLOAD,
			"Message size is too big. (%zu > %zu)",
			capacity, JNLBUFFER_MAX_PAYLOAD))
		return -EINVAL;

	buffer->len = 0;
	buffer->capacity = capacity;
	buffer->data = __wkmalloc("jnlbuffer.data", capacity, GFP_ATOMIC);
	if (!buffer->data)
		return -ENOMEM;

	response.error_code = 0;
	response.pending_data = false;
	error = jnlbuffer_write(buffer, &response, sizeof(response));
	if (error)
		__wkfree("jnlbuffer.data", buffer->data);

	return error;
}

int jnlbuffer_init_max(struct jnl_buffer *buffer, struct genl_info *info)
{
	return jnlbuffer_init(buffer, info, JNLBUFFER_MAX_SIZE);
}

void jnlbuffer_free(struct jnl_buffer *buffer)
{
	__wkfree("jnlbuffer.data", buffer->data);
}

int jnlbuffer_write(struct jnl_buffer *buffer, void *data, size_t data_size)
{
	if (buffer->len + data_size > buffer->capacity) {
		log_debug("The buffer's storage capacity has been surpassed.");
		/* TODO getter? */
		((struct response_hdr *)buffer->data)->pending_data = true;
		return 1;
	}

	memcpy(buffer->data + buffer->len, data, data_size);
	buffer->len += data_size;
	return 0;
}

int jnlbuffer_send(struct jnl_buffer *buffer, struct genl_info *info)
{
	struct sk_buff *skb;
	void *msg_head;
	int error;
	uint32_t portid;

	if (buffer->len > JNLBUFFER_MAX_PAYLOAD) {
		pr_err("The response is too long; cannot send to userspace.\n");
		return -EINVAL;
	}

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
