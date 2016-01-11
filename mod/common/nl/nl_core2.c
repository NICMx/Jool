#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>
#include "nat64/common/config.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/common/nl/nl_core2.h"

#include "nat64/common/genetlink.h"


#define NL_CORE_BUFFER_TOTAL_SIZE 2000
#define NL_CORE_BUFFER_DATA_SIZE	NL_CORE_BUFFER_TOTAL_SIZE - sizeof(struct nl_core_buffer)


static int genetlink_callback(struct sk_buff *skb_in, struct genl_info *info);


/**
 * Actual message type definition.
 */
struct genl_ops ops[] = {{ .cmd = JOOL_COMMAND, .flags = 0, .doit =	genetlink_callback, .dumpit = NULL}, };


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


	skb = genlmsg_new(sizeof(*buffer)+buffer->len, GFP_KERNEL);
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


	error = nla_put(skb, ATTR_DATA, sizeof(*buffer)+buffer->len, buffer);
	if (error) {
		pr_err("nla_put() failed. \n");
		kfree_skb(skb);
		return -EINVAL;
	}
	total_length = genlmsg_end(skb, msg_head);


	error = genlmsg_reply(skb, info);
	if (error) {
		pr_err("genlmsg_reply() failed: %d\n", error);
		return error;
	}

	return 0;

}

size_t nl_core_data_max_size(void)
{
	return NL_CORE_BUFFER_DATA_SIZE;
}

int nl_core_new_core_buffer(struct nl_core_buffer **out_buffer, size_t size)
{
	struct nl_core_buffer *buffer;

	if (size > NL_CORE_BUFFER_DATA_SIZE) {
		log_err("Invalid data size for buffer, maximum allowed size is %u", NL_CORE_BUFFER_DATA_SIZE);
		return -EINVAL;
	}

	buffer = kmalloc(sizeof(struct nl_core_buffer) + size, GFP_ATOMIC);
	(*out_buffer) = (struct nl_core_buffer *)buffer;

	if (!(*out_buffer)) {
		log_err("Could not allocate memory for nl_core_buffer!");
		return -ENOMEM;
	}

	buffer->error_code = 0;
	buffer->len = 0;
	buffer->capacity = size;
	buffer->pending_data = false;

	return 0;
}

void nl_core_free_buffer(struct nl_core_buffer *buffer)
{
	struct nl_core_buffer *internal_buffer = (struct nl_core_buffer *) buffer;

	if (internal_buffer != NULL)
		kfree(internal_buffer);
	else
		log_warn_once("Trying to free unallocated buffer!");

}

bool nl_core_write_to_buffer(struct nl_core_buffer *buffer, __u8 *data, size_t data_length)
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

int nl_core_send_multicast_message(struct nl_core_buffer * buffer, struct genl_multicast_group *grp)
{
	int error = 0;
	struct sk_buff *skb_out;
	void *data;

	 skb_out = nlmsg_new(NLMSG_ALIGN(buffer->len), GFP_ATOMIC);

	 if (!skb_out) {
			log_debug("Failed to allocate the multicast message.");
			return -ENOMEM;
	 }

	data = genlmsg_put(skb_out, 0, 0, &jool_family,0,0);

	memcpy(data, (buffer+1), buffer->len);

	error = genlmsg_multicast_allns(skb_out, 0, grp->id, 0);


	if (error) {
		log_warn_once("Sending multicast message failed. (errcode %d)", error);
		return error;
	}

	return 0;
}

int nl_core_send_buffer(struct genl_info *info, enum config_mode command, struct nl_core_buffer *buffer)
{

	if (buffer->len > (size_t)NL_CORE_BUFFER_DATA_SIZE) {
		log_err("Buffer too long to be sent!");
		return -EINVAL;
	}

	return respond_single_msg(info, command, buffer);
}

int nl_core_respond_error(struct genl_info *info, enum config_mode command, int error_code)
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


	error = nl_core_new_core_buffer(&buffer, (size_t) msg_length);

	if (error) {
		log_err("Error while trying to allocate buffer for sending error message!");
		return error;
	}


	buffer->error_code = error_code;

	error = nl_core_write_to_buffer(buffer, (__u8 *)error_msg, (size_t) msg_length);

	if (error) {
		log_err("Error while trying to write to buffer for sending error message!");
		return error;
	}

	error = respond_single_msg(info, command, buffer);

	kfree(error_msg);
	nl_core_free_buffer(buffer);

	return error;

}

int nl_core_send_acknowledgement(struct genl_info *info, enum config_mode command)
{
	int error = 0;
	struct nl_core_buffer *buffer;

	error = nl_core_new_core_buffer(&buffer, 0);

	if (error) {
		log_err("Error while trying to allocate buffer for sending acknowledgement!");
		return error;
	}

	buffer->error_code = 0;
	buffer->len = 0;

	error = respond_single_msg(info, command, buffer);

	nl_core_free_buffer(buffer);

	return error;
}

int nl_core_register_mc_group(struct genl_multicast_group *grp)
{
	int error = 0;

	if (!grp) {
		log_err("Trying to register a NULL multicast group!");
		return -EINVAL;
	}

	error = genl_register_mc_group(&jool_family, grp);


	if (error) {
		log_err("Error while registering multicast group %s for family %s",
				grp->name, jool_family.name);
		return error;
	}

	return 0;
}

static int register_family(struct genl_family *family, struct genl_ops* ops,
		size_t n_ops)
{

	int error = 0;

	pr_info("Registering family.\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)

	error = genl_register_family_with_ops(family, ops, n_ops);

#else
	error = genl_register_family_with_ops(family, ops);

#endif

	if (error) {
		pr_err("Family registration failed: %d\n", error);
		return error;
	}

	pr_info("Jool module registered.\n");

	return error;
}

void nl_core_set_main_callback(int (*cb)(struct sk_buff *skb_in, struct genl_info *info))
{
	main_callback = cb;
}

int nl_core_init(void)
{
	error_pool_init();
	return register_family(&jool_family, ops, 1);
}

int nl_core_destroy(void)
{
	error_pool_destroy();
	return genl_unregister_family(&jool_family);
}
