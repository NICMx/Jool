#include "nat64/mod/config.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/out_stream.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/static_routes.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/translate_packet.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <net/sock.h>
#include <net/netlink.h>


/**
 * Socket the userspace application will speak to.
 */
struct sock *nl_socket;

/**
 * A lock, used to avoid sync issues when receiving messages from userspace.
 */
static DEFINE_MUTEX(my_mutex);


/**
 * Use this when data_len is known to be smaller than BUFFER_SIZE. When this might not be the case,
 * use the output stream instead (out_stream.h).
 */
static int respond_single_msg(struct nlmsghdr *nl_hdr_in, int type, void *payload, int payload_len)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_hdr_out;
	int res;

	skb_out = nlmsg_new(NLMSG_ALIGN(payload_len), GFP_ATOMIC);
	if (!skb_out) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a response skb to the user.");
		return -ENOMEM;
	}

	nl_hdr_out = nlmsg_put(skb_out,
			0, /* src_pid (0 = kernel) */
			nl_hdr_in->nlmsg_seq, /* seq */
			type, /* type */
			payload_len, /* payload len */
			0); /* flags */
	memcpy(nlmsg_data(nl_hdr_out), payload, payload_len);
	/* NETLINK_CB(skb_out).dst_group = 0; */

	res = nlmsg_unicast(nl_socket, skb_out, nl_hdr_in->nlmsg_pid);
	if (res < 0) {
		log_err(ERR_NETLINK, "Error code %d while returning response to the user.", res);
		return res;
	}

	return 0;
}

static int respond_setcfg(struct nlmsghdr *nl_hdr_in, void *payload, int payload_len)
{
	return respond_single_msg(nl_hdr_in, MSG_SETCFG, payload, payload_len);
}

/**
 * @note "ACK messages also use the message type NLMSG_ERROR and payload format but the error code
 * is set to 0." (http://www.infradead.org/~tgr/libnl/doc/core.html#core_msg_ack).
 */
static int respond_error(struct nlmsghdr *nl_hdr_in, int error)
{
	struct nlmsgerr payload = { abs(error), *nl_hdr_in };
	return respond_single_msg(nl_hdr_in, NLMSG_ERROR, &payload, sizeof(payload));
}

/*
static int respond_ack(struct nlmsghdr *nl_hdr_in)
{
	return respond_error(nl_hdr_in, 0);
}
*/

static int pool6_entry_to_userspace(struct ipv6_prefix *prefix, void *arg)
{
	struct out_stream *stream = (struct out_stream *) arg;
	stream_write(stream, prefix, sizeof(*prefix));
	return 0;
}

static int handle_pool6_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		union request_pool6 *request)
{
	struct out_stream *stream;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv6 pool to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err(ERR_ALLOC_FAILED, "Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		error = pool6_for_each(pool6_entry_to_userspace, stream);
		stream_close(stream);

		kfree(stream);
		return error;

	case OP_ADD:
		log_debug("Adding a prefix to the IPv6 pool.");
		return respond_error(nl_hdr, pool6_register(&request->update.prefix));

	case OP_REMOVE:
		log_debug("Removing a prefix from the IPv6 pool.");
		return respond_error(nl_hdr, pool6_remove(&request->update.prefix));

	default:
		log_err(ERR_UNKNOWN_OP, "Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int pool4_entry_to_userspace(struct in_addr *address, void *arg)
{
	struct out_stream *stream = (struct out_stream *) arg;
	stream_write(stream, address, sizeof(*address));
	return 0;
}

static int handle_pool4_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		union request_pool4 *request)
{
	struct out_stream *stream;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv4 pool to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err(ERR_ALLOC_FAILED, "Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		error = pool4_for_each(pool4_entry_to_userspace, stream);
		stream_close(stream);

		kfree(stream);
		return error;

	case OP_ADD:
		log_debug("Adding an address to the IPv4 pool.");
		return respond_error(nl_hdr, pool4_register(&request->update.addr));

	case OP_REMOVE:
		log_debug("Removing an address from the IPv4 pool.");
		return respond_error(nl_hdr, pool4_remove(&request->update.addr));

	default:
		log_err(ERR_UNKNOWN_OP, "Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int bib_entry_to_userspace(struct bib_entry *entry, void *arg)
{
	struct out_stream *stream = (struct out_stream *) arg;
	struct bib_entry_us entry_us;

	entry_us.ipv4 = entry->ipv4;
	entry_us.ipv6 = entry->ipv6;
	entry_us.is_static = entry->is_static;

	stream_write(stream, &entry_us, sizeof(entry_us));
	return 0;
}

static int handle_bib_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct request_bib *request)
{
	struct out_stream *stream;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending BIB to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err(ERR_ALLOC_FAILED, "Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		spin_lock_bh(&bib_session_lock);
		error = bib_for_each(request->l4_proto, bib_entry_to_userspace, stream);
		spin_unlock_bh(&bib_session_lock);
		stream_close(stream);

		kfree(stream);
		return error;

	case OP_ADD:
		log_debug("Adding BIB entry.");
		return respond_error(nl_hdr, add_static_route(request));

	case OP_REMOVE:
		log_debug("Removing BIB entry.");
		return respond_error(nl_hdr, delete_static_route(request));

	default:
		log_err(ERR_UNKNOWN_OP, "Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int session_entry_to_userspace(struct session_entry *entry, void *arg)
{
	struct out_stream *stream = (struct out_stream *) arg;
	struct session_entry_us entry_us;

	entry_us.ipv6 = entry->ipv6;
	entry_us.ipv4 = entry->ipv4;
	entry_us.dying_time = entry->dying_time - jiffies_to_msecs(jiffies);
	entry_us.l4_proto = entry->l4_proto;

	stream_write(stream, &entry_us, sizeof(entry_us));
	return 0;
}

static int handle_session_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct request_session *request)
{
	struct out_stream *stream;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending session table to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err(ERR_ALLOC_FAILED, "Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		spin_lock_bh(&bib_session_lock);
		error = session_for_each(request->l4_proto, session_entry_to_userspace, stream);
		spin_unlock_bh(&bib_session_lock);
		stream_close(stream);

		kfree(stream);
		return error;

	default:
		log_err(ERR_UNKNOWN_OP, "Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int handle_filtering_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct filtering_config *request)
{
	struct filtering_config clone;
	int error;

	if (nat64_hdr->operation == 0) {
		log_debug("Returning 'Filtering and Updating' options.");

		error = clone_filtering_config(&clone);
		if (error)
			return respond_error(nl_hdr, error);

		return respond_setcfg(nl_hdr, &clone, sizeof(clone));
	} else {
		log_debug("Updating 'Filtering and Updating' options.");
		return respond_error(nl_hdr, set_filtering_config(nat64_hdr->operation, request));
	}
}

static int handle_fragmentation_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct filtering_config *request)
{
	struct filtering_config clone;
	int error;

	if (nat64_hdr->operation == 0) {
		log_debug("Returning 'Fragmentation' options.");

		error = clone_filtering_config(&clone);
		if (error)
			return respond_error(nl_hdr, error);

		return respond_setcfg(nl_hdr, &clone, sizeof(clone));
	} else {
		log_debug("Updating 'Fragmentation' options.");
		return respond_error(nl_hdr, set_fragmentation_config(nat64_hdr->operation, request));
	}
}

static int handle_translate_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct translate_config *request)
{
	int error;

	if (nat64_hdr->operation == 0) {
		struct translate_config clone;
		unsigned char *config;
		__u16 config_len;

		log_debug("Returning 'Translate the Packet' options.");

		error = clone_translate_config(&clone);
		if (error)
			return respond_error(nl_hdr, error);

		error = serialize_translate_config(&clone, &config, &config_len);
		if (error)
			return respond_error(nl_hdr, error);

		error = respond_setcfg(nl_hdr, config, config_len);
		kfree(config);
		kfree(clone.mtu_plateaus);
		return error;
	} else {
		struct translate_config new_config;

		log_debug("Updating 'Translate the Packet' options.");

		error = deserialize_translate_config(request, nat64_hdr->length - sizeof(*nat64_hdr),
				&new_config);
		if (error)
			return respond_error(nl_hdr, error);

		error = respond_error(nl_hdr, set_translate_config(nat64_hdr->operation, &new_config));
		kfree(new_config.mtu_plateaus);
		return error;
	}
}

/**
 * Gets called by "netlink_rcv_skb" when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 * @param nlh message's metadata.
 * @return result status.
 */
static int handle_netlink_message(struct sk_buff *skb_in, struct nlmsghdr *nl_hdr)
{
	struct request_hdr *nat64_hdr;
	void *request;
	int error;

	if (nl_hdr->nlmsg_type != MSG_TYPE_NAT64) {
		log_debug("Expecting %#x but got %#x.", MSG_TYPE_NAT64, nl_hdr->nlmsg_type);
		return -EINVAL;
	}

	nat64_hdr = NLMSG_DATA(nl_hdr);
	request = nat64_hdr + 1;

	switch (nat64_hdr->mode) {
	case MODE_POOL6:
		error = handle_pool6_config(nl_hdr, nat64_hdr, request);
		break;
	case MODE_POOL4:
		error = handle_pool4_config(nl_hdr, nat64_hdr, request);
		break;
	case MODE_BIB:
		error = handle_bib_config(nl_hdr, nat64_hdr, request);
		break;
	case MODE_SESSION:
		error = handle_session_config(nl_hdr, nat64_hdr, request);
		break;
	case MODE_FILTERING:
		error = handle_filtering_config(nl_hdr, nat64_hdr, request);
		break;
	case MODE_TRANSLATE:
		error = handle_translate_config(nl_hdr, nat64_hdr, request);
		break;
	case MODE_FRAGMENTATION:
		error = handle_fragmentation_config(nl_hdr, nat64_hdr, request);
		break;
	default:
		log_err(ERR_UNKNOWN_OP, "Unknown configuration mode: %d", nat64_hdr->mode);
		error = respond_error(nl_hdr, -EINVAL);
	}

	return error;
}

/**
 * Gets called by Netlink when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 */
static void receive_from_userspace(struct sk_buff *skb)
{
	log_debug("Message arrived.");
	mutex_lock(&my_mutex);
	netlink_rcv_skb(skb, &handle_netlink_message);
	mutex_unlock(&my_mutex);
}

int config_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, receive_from_userspace,
			NULL, THIS_MODULE);
#else
	struct netlink_kernel_cfg nl_cfg = {
		.groups = 0,
		.input  = receive_from_userspace,
		.cb_mutex = NULL,
	};
	nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &nl_cfg); 
#endif
	
	if (!nl_socket) {
		log_err(ERR_NETLINK, "Creation of netlink socket failed.");
		return -EINVAL;
	}
	log_debug("Netlink socket created.");

	return 0;
}

void config_destroy(void)
{
	netlink_kernel_release(nl_socket);
}
