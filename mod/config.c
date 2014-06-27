#include "nat64/mod/config.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/out_stream.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/session_db.h"
#include "nat64/mod/static_routes.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/translate_packet.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>


/**
 * Socket the userspace application will speak to.
 */
static struct sock *nl_socket;

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
		log_err("Failed to allocate a response skb to the user.");
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
		log_err("Error code %d while returning response to the user.", res);
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

static int verify_superpriv(struct request_hdr *nat64_hdr)
{
	if (!capable(CAP_NET_ADMIN)) {
		log_err("Administrative privileges required: %d", nat64_hdr->operation);
		return -EPERM;
	}

	return 0;
}

static int pool6_entry_to_userspace(struct ipv6_prefix *prefix, void *arg)
{
	struct out_stream *stream = (struct out_stream *) arg;
	return stream_write(stream, prefix, sizeof(*prefix));
}

static int handle_pool6_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		union request_pool6 *request)
{
	struct out_stream *stream;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv6 pool to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err("Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		error = pool6_for_each(pool6_entry_to_userspace, stream);
		stream_close(stream);

		kfree(stream);
		return error;

	case OP_COUNT:
		log_debug("Returning IPv6 prefix count.");
		error = pool6_count(&count);
		if (error)
			return respond_error(nl_hdr, error);
		return respond_setcfg(nl_hdr, &count, sizeof(count));

	case OP_ADD:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Adding a prefix to the IPv6 pool.");
		return respond_error(nl_hdr, pool6_add(&request->update.prefix));

	case OP_REMOVE:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Removing a prefix from the IPv6 pool.");
		return respond_error(nl_hdr, pool6_remove(&request->update.prefix));

	default:
		log_err("Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int pool4_entry_to_userspace(struct pool4_node *node, void *arg)
{
	return stream_write(arg, &node->addr, sizeof(node->addr));
}

static int handle_pool4_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		union request_pool4 *request)
{
	struct out_stream *stream;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv4 pool to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err("Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		error = pool4_for_each(pool4_entry_to_userspace, stream);
		stream_close(stream);

		kfree(stream);
		return error;

	case OP_COUNT:
		log_debug("Returning IPv4 address count.");
		error = pool4_count(&count);
		if (error)
			return respond_error(nl_hdr, error);
		return respond_setcfg(nl_hdr, &count, sizeof(count));

	case OP_ADD:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Adding an address to the IPv4 pool.");
		return respond_error(nl_hdr, pool4_register(&request->update.addr));

	case OP_REMOVE:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Removing an address from the IPv4 pool.");

		error = sessiondb_delete_by_ipv4(&request->update.addr);
		if (error)
			return respond_error(nl_hdr, error);

		error = bibdb_delete_by_ipv4(&request->update.addr);
		if (error)
			return respond_error(nl_hdr, error);

		return respond_error(nl_hdr, pool4_remove(&request->update.addr));

	default:
		log_err("Unknown operation: %d", nat64_hdr->operation);
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

	return stream_write(stream, &entry_us, sizeof(entry_us));
}

static int handle_bib_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct request_bib *request)
{
	struct out_stream *stream;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending BIB to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err("Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		error = bibdb_iterate_by_ipv4(request->l4_proto, &request->display.ipv4,
				!request->display.iterate, bib_entry_to_userspace, stream);
		if (error > 0) {
			error = stream_close_continue(stream);
		} else {
			error = stream_close(stream);
		}

		kfree(stream);
		return error;

	case OP_COUNT:
		log_debug("Returning BIB count.");
		error = bibdb_count(request->l4_proto, &count);
		if (error)
			return respond_error(nl_hdr, error);
		return respond_setcfg(nl_hdr, &count, sizeof(count));

	case OP_ADD:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Adding BIB entry.");
		return respond_error(nl_hdr, add_static_route(request));

	case OP_REMOVE:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Removing BIB entry.");
		return respond_error(nl_hdr, delete_static_route(request));

	default:
		log_err("Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int session_entry_to_userspace(struct session_entry *entry, void *arg)
{
	struct out_stream *stream = (struct out_stream *) arg;
	struct session_entry_us entry_us;

	entry_us.ipv6 = entry->ipv6;
	entry_us.ipv4 = entry->ipv4;
	entry_us.dying_time = jiffies_to_msecs(entry->dying_time - jiffies);
	entry_us.l4_proto = entry->l4_proto;

	return stream_write(stream, &entry_us, sizeof(entry_us));
}

static int handle_session_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct request_session *request)
{
	struct out_stream *stream;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending session table to userspace.");

		stream = kmalloc(sizeof(*stream), GFP_ATOMIC);
		if (!stream) {
			log_err("Could not allocate an output stream to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		stream_init(stream, nl_socket, nl_hdr);
		error = sessiondb_iterate_by_ipv4(request->l4_proto, &request->ipv4, !request->iterate,
				session_entry_to_userspace, stream);
		if (error > 0) {
			error = stream_close_continue(stream);
		} else {
			error = stream_close(stream);
		}

		kfree(stream);
		return error;

	case OP_COUNT:
		log_debug("Returning session count.");
		error = sessiondb_count(request->l4_proto, &count);
		if (error)
			return respond_error(nl_hdr, error);
		return respond_setcfg(nl_hdr, &count, sizeof(count));

	default:
		log_err("Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int handle_filtering_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct full_filtering_config *request)
{
	struct full_filtering_config clone;
	int error;

	if (nat64_hdr->operation == 0) {
		log_debug("Returning 'Filtering and Updating' options.");

		error = clone_filtering_config(&clone.filtering);
		if (error)
			return respond_error(nl_hdr, error);
		error = sessiondb_clone_config(&clone.sessiondb);
		if (error)
			return respond_error(nl_hdr, error);

		clone.sessiondb.ttl.udp = jiffies_to_msecs(clone.sessiondb.ttl.udp);
		clone.sessiondb.ttl.tcp_est = jiffies_to_msecs(clone.sessiondb.ttl.tcp_est);
		clone.sessiondb.ttl.tcp_trans = jiffies_to_msecs(clone.sessiondb.ttl.tcp_trans);
		clone.sessiondb.ttl.icmp = jiffies_to_msecs(clone.sessiondb.ttl.icmp);

		return respond_setcfg(nl_hdr, &clone, sizeof(clone));
	} else {
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Updating 'Filtering and Updating' options.");

		request->sessiondb.ttl.udp = msecs_to_jiffies(request->sessiondb.ttl.udp);
		request->sessiondb.ttl.tcp_est = msecs_to_jiffies(request->sessiondb.ttl.tcp_est);
		request->sessiondb.ttl.tcp_trans = msecs_to_jiffies(request->sessiondb.ttl.tcp_trans);
		request->sessiondb.ttl.icmp = msecs_to_jiffies(request->sessiondb.ttl.icmp);

		error = set_filtering_config(nat64_hdr->operation, &request->filtering);
		if (error)
			return respond_error(nl_hdr, error);
		error = sessiondb_set_config(nat64_hdr->operation, &request->sessiondb);

		return respond_error(nl_hdr, error);
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

		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

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

	if (nl_hdr->nlmsg_type != MSG_TYPE_JOOL) {
		log_debug("Expecting %#x but got %#x.", MSG_TYPE_JOOL, nl_hdr->nlmsg_type);
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
	default:
		log_err("Unknown configuration mode: %d", nat64_hdr->mode);
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
	/*
	 * The function changed between Linux 3.5.7 and 3.6, and then again from 3.6.11 to 3.7.
	 *
	 * If you're reading the kernel's Git history, that appears to be the commit
	 * a31f2d17b331db970259e875b7223d3aba7e3821 (v3.6-rc1~125^2~337) and then again in
	 * 9f00d9776bc5beb92e8bfc884a7e96ddc5589e2e (v3.7-rc1~145^2~194).
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
	nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, receive_from_userspace,
			NULL, THIS_MODULE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	struct netlink_kernel_cfg nl_cfg = { .input  = receive_from_userspace };
	nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, THIS_MODULE, &nl_cfg);
#else
	struct netlink_kernel_cfg nl_cfg = { .input  = receive_from_userspace };
	nl_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &nl_cfg);
#endif
	
	if (!nl_socket) {
		log_err("Creation of netlink socket failed.");
		return -EINVAL;
	}
	log_debug("Netlink socket created.");

	return 0;
}

void config_destroy(void)
{
	netlink_kernel_release(nl_socket);
}
