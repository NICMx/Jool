#include "nat64/mod/common/nl/nl_core2.h"

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>
#include "nat64/common/config.h"
#include "nat64/mod/common/types.h"

#include "nat64/common/genetlink.h"


#define NL_CORE_BUFFER_TOTAL_SIZE 2000
#define NL_CORE_BUFFER_DATA_SIZE (NL_CORE_BUFFER_TOTAL_SIZE - sizeof(struct nl_core_buffer))


static int genetlink_callback(struct sk_buff *skb_in, struct genl_info *info);

struct genl_multicast_group mc_groups[1] = {
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
struct genl_ops ops[] = {
	{
		.cmd = JOOL_COMMAND,
		.flags = 0,
		.doit = genetlink_callback,
		.dumpit = NULL,
	},
};


/**
 * A Generic Netlink family is a group of listeners who can and want to speak
 * your language.
 * Anyone who wants to hear your messages needs to register to the same family
 * as you.
 */
struct genl_family jool_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = GNL_JOOL_FAMILY_NAME,
	.version = 1,
	.maxattr = __ATTR_MAX,
};

int (*main_callback)(struct sk_buff *skb_in, struct genl_info *info) = NULL;

static int genetlink_callback(struct sk_buff *skb_in, struct genl_info *info)
{
	if (main_callback != NULL) {
		log_info("calling main callback!");
		return main_callback(skb_in, info);
	} else {
		log_warn_once("Wanted to call main callback but it is null!");
	}
	return -EINVAL;
}

static int respond_single_msg(struct genl_info *info, enum config_mode command,	struct nl_core_buffer *buffer)
{
	struct sk_buff *skb;
	void *msg_head;
	int error;
	int total_length;
	uint32_t portid;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	portid = info->snd_pid;
#else
	portid = info->snd_portid;
#endif

	skb = genlmsg_new(sizeof(*buffer) + buffer->len, GFP_KERNEL);
	if (!skb) {
		pr_err("genlmsg_new() failed.\n");
		return -ENOMEM;
	}

	msg_head = genlmsg_put(skb, portid, 0, &jool_family, 0, command);
	if (!msg_head) {
		pr_err("genlmsg_put() failed.\n");
		kfree_skb(skb);
		return -ENOMEM;
	}

	error = nla_put(skb, ATTR_DATA, (int)(sizeof(*buffer) + buffer->len), buffer);
	if (error) {
		pr_err("nla_put() failed. \n");
		kfree_skb(skb);
		return error;
	}

	total_length = genlmsg_end(skb, msg_head);

	error = genlmsg_reply(skb, info);
	if (error) {
		pr_err("genlmsg_reply() failed: %d\n", error);
		return error;
	}

	return 0;
}

size_t nlbuffer_data_max_size(void)
{
	return NL_CORE_BUFFER_DATA_SIZE;
}

int nlbuffer_new(struct nl_core_buffer **out_buffer, size_t capacity)
{
	struct nl_core_buffer *buffer;

	if (WARN(capacity > NL_CORE_BUFFER_DATA_SIZE, "Message size is too big.")) {
		log_err("Message size is too big. (%zu > %zu)", capacity,
				NL_CORE_BUFFER_DATA_SIZE);
		return -EINVAL;
	}

	buffer = kmalloc(sizeof(*buffer) + capacity, GFP_ATOMIC);
	if (!buffer) {
		log_err("Could not allocate memory for nl_core_buffer!");
		return -ENOMEM;
	}

	buffer->error_code = 0;
	buffer->len = 0;
	buffer->capacity = capacity;
	buffer->pending_data = false;

	*out_buffer = buffer;
	return 0;
}

void nlbuffer_free(struct nl_core_buffer *buffer)
{
	kfree(buffer);
}

bool nlbuffer_write(struct nl_core_buffer *buffer, void *data,
		size_t data_length)
{
	__u8 *buffer_data;

	if (buffer->len + data_length > buffer->capacity) {
		log_debug("The buffer's storage capacity has been surpassed!");
		buffer->pending_data = true;
		return 1;
	}

	buffer_data = (__u8 *)(buffer + 1);

	buffer->len += data_length;
	memcpy(buffer_data, data, data_length);

	return 0;
}

int nlcore_send_multicast_message(struct nl_core_buffer *buffer)
{
	int error = 0;
	struct sk_buff *skb_out;
	void *msg_head;

	skb_out = nlmsg_new(NLMSG_ALIGN(buffer->len), GFP_ATOMIC);
	if (!skb_out) {
		log_debug("Failed to allocate the multicast message.");
		return -ENOMEM;
	}

	msg_head = genlmsg_put(skb_out, 0, 0, &jool_family, 0, 0);
	if (msg_head) {
		log_err("genlmsg_put() returned NULL.");
		return -EINVAL;
	}

	error = nla_put(skb_out, ATTR_DATA, sizeof(*buffer) + buffer->len, buffer);
	if (error) {
		pr_err("nla_put() failed. \n");
		kfree_skb(skb_out);
		return -EINVAL;
	}

	genlmsg_end(skb_out, msg_head);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	error = genlmsg_multicast_allns(skb_out, 0, mc_groups[0].id, 0);
#else
	error = genlmsg_multicast_allns(&jool_family, skb_out, 0, 0, GFP_ATOMIC);
#endif

	if (error) {
		log_warn_once("Sending multicast message failed. (errcode %d)",
				error);
		return error;
	}

	return 0;
}

int nlbuffer_send(struct genl_info *info, enum config_mode command, struct nl_core_buffer *buffer)
{
	log_info("sending buffer!");
	if (buffer->len > (size_t)NL_CORE_BUFFER_DATA_SIZE) {
		log_err("Buffer too long to be sent!");
		return -EINVAL;
	}

	return respond_single_msg(info, command, buffer);
}

int nlcore_respond_error(struct genl_info *info, enum config_mode command, int error_code)
{
	struct nl_core_buffer *buffer;
	int error = 0;
	char *error_msg;
	unsigned int msg_length = 0;

	error_pool_get_message(&error_msg, &msg_length);

	if (msg_length > (unsigned int)NL_CORE_BUFFER_DATA_SIZE) {
		log_err("Error message too long to fit in the buffer!");
		return -EINVAL;
	}

	log_info("msg len: %d", msg_length);


	error = nlbuffer_new(&buffer, (size_t) msg_length);

	if (error) {
		log_err("Error while trying to allocate buffer for sending error message!");
		return error;
	}


	buffer->error_code = error_code;

	error = nlbuffer_write(buffer, error_msg, (size_t) msg_length);

	if (error) {
		log_err("Error while trying to write to buffer for sending error message!");
		return error;
	}

	error = respond_single_msg(info, command, buffer);

	kfree(error_msg);
	nlbuffer_free(buffer);

	return error;

}

int nlcore_send_ack(struct genl_info *info, enum config_mode command)
{
	int error = 0;
	struct nl_core_buffer *buffer;

	error = nlbuffer_new(&buffer, 0);
	if (error) {
		log_err("Error while trying to allocate buffer for sending acknowledgement!");
		return error;
	}

	buffer->error_code = 0;
	buffer->len = 0;

	error = respond_single_msg(info, command, buffer);

	nlbuffer_free(buffer);

	return error;
}


int nlcore_respond(struct genl_info *info, enum config_mode command, int error)
{
	if (error)
		return nlcore_respond_error(info, command, error);
	else
		return nlcore_send_ack(info, command);
}

int nlcore_respond_struct(struct genl_info *info, enum config_mode command,
		void *content, size_t content_len)
{
	struct nl_core_buffer *buffer;
	int error;

	error = nlbuffer_new(&buffer, content_len);
	if (error)
		return nlcore_respond_error(info, command, error);

	error = nlbuffer_write(buffer, content, content_len);
	if (error < 0)
		return nlcore_respond_error(info, command, error);
	/*
	 * @content is supposed to be a statically-defined struct, and as such
	 * should be several orders smaller than the Netlink packet size limit.
	 */
	if (WARN(error > 0, "Content exceeds the maximum packet size."))
		return nlcore_respond_error(info, command, -E2BIG);

	error = nlbuffer_send(info, command, buffer);
	nlbuffer_free(buffer);
	return error;
}


static int register_family(void)
{
	int error;

	log_info("Registering family.");

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

	log_info("Jool module registered.");
	return 0;
}

void nlcore_set_main_callback(int (*cb)(struct sk_buff *skb_in, struct genl_info *info))
{
	log_info("setting main callback!");
	main_callback = cb;
}

int nlcore_init(void)
{
	error_pool_init();
	return register_family();
}

void nlcore_destroy(void)
{
	genl_unregister_family(&jool_family);
	error_pool_destroy();
}
