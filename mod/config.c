#include "nat64/mod/config.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/nl_buffer.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/session_db.h"
#include "nat64/mod/static_routes.h"
#include "nat64/mod/pkt_queue.h"
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
 * Use this when data_len is known to be smaller than NLBUFFER_SIZE. When this might not be the
 * case, use the netlink buffer instead (nl_buffer.h).
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
	struct nl_buffer *buffer = (struct nl_buffer *) arg;
	return nlbuffer_write(buffer, prefix, sizeof(*prefix));
}

static int handle_pool6_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		union request_pool6 *request)
{
	struct nl_buffer *buffer;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv6 pool to userspace.");

		buffer = kmalloc(sizeof(*buffer), GFP_ATOMIC);
		if (!buffer) {
			log_err("Could not allocate an output buffer to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		nlbuffer_init(buffer, nl_socket, nl_hdr);
		error = pool6_for_each(pool6_entry_to_userspace, buffer);
		nlbuffer_close(buffer);

		kfree(buffer);
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

		return respond_error(nl_hdr, pool6_add(&request->add.prefix));

	case OP_REMOVE:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Removing a prefix from the IPv6 pool.");
		error = pool6_remove(&request->remove.prefix);
		if (error)
			return respond_error(nl_hdr, error);

		if (!request->flush.quick)
			error = sessiondb_delete_by_ipv6_prefix(&request->remove.prefix);

		return respond_error(nl_hdr, error);

	case OP_FLUSH:
		if (verify_superpriv(nat64_hdr)) {
			return respond_error(nl_hdr, -EPERM);
		}

		log_debug("Flushing the IPv6 pool...");
		error = pool6_flush();
		if (error)
			return respond_error(nl_hdr, error);

		if (!request->flush.quick)
			error = sessiondb_flush();

		return respond_error(nl_hdr, error);

	default:
		log_err("Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int pool4_entry_to_userspace(struct pool4_node *node, void *arg)
{
	return nlbuffer_write(arg, &node->addr, sizeof(node->addr));
}

static int handle_pool4_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		union request_pool4 *request)
{
	struct nl_buffer *buffer;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv4 pool to userspace.");

		buffer = kmalloc(sizeof(*buffer), GFP_ATOMIC);
		if (!buffer) {
			log_err("Could not allocate an output buffer to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		nlbuffer_init(buffer, nl_socket, nl_hdr);
		error = pool4_for_each(pool4_entry_to_userspace, buffer);
		nlbuffer_close(buffer);

		kfree(buffer);
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
		return respond_error(nl_hdr, pool4_register(&request->add.addr));

	case OP_REMOVE:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Removing an address from the IPv4 pool.");

		error = pool4_remove(&request->remove.addr);
		if (error)
			return respond_error(nl_hdr, error);

		if (!request->remove.quick) {
			error = sessiondb_delete_by_ipv4(&request->remove.addr);
			if (error)
				return respond_error(nl_hdr, error);
			error = bibdb_delete_by_ipv4(&request->remove.addr);
		}

		return respond_error(nl_hdr, error);

	case OP_FLUSH:
		if (verify_superpriv(nat64_hdr)) {
			return respond_error(nl_hdr, -EPERM);
		}

		log_debug("Flushing the IPv4 pool...");
		error = pool4_flush();
		if (error)
			return respond_error(nl_hdr, error);

		if (!request->flush.quick) {
			error = sessiondb_flush();
			if (error)
				return respond_error(nl_hdr, error);
			error = bibdb_flush();
		}

		return respond_error(nl_hdr, error);

	default:
		log_err("Unknown operation: %d", nat64_hdr->operation);
		return respond_error(nl_hdr, -EINVAL);
	}
}

static int bib_entry_to_userspace(struct bib_entry *entry, void *arg)
{
	struct nl_buffer *buffer = (struct nl_buffer *) arg;
	struct bib_entry_usr entry_usr;

	entry_usr.addr4 = entry->ipv4;
	entry_usr.addr6 = entry->ipv6;
	entry_usr.is_static = entry->is_static;

	return nlbuffer_write(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_bib_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct request_bib *request)
{
	struct nl_buffer *buffer;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending BIB to userspace.");

		buffer = kmalloc(sizeof(*buffer), GFP_ATOMIC);
		if (!buffer) {
			log_err("Could not allocate an output buffer to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		nlbuffer_init(buffer, nl_socket, nl_hdr);
		error = bibdb_iterate_by_ipv4(request->l4_proto, &request->display.addr4,
				!request->display.iterate, bib_entry_to_userspace, buffer);
		if (error > 0) {
			error = nlbuffer_close_continue(buffer);
		} else {
			error = nlbuffer_close(buffer);
		}

		kfree(buffer);
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
	struct nl_buffer *buffer = (struct nl_buffer *) arg;
	struct session_entry_usr entry_usr;
	unsigned long dying_time;
	int error;

	error = sessiondb_get_timeout(entry, &dying_time);
	if (error)
		return error;
	dying_time += entry->update_time;

	entry_usr.addr6 = entry->ipv6;
	entry_usr.addr4 = entry->ipv4;
	entry_usr.state = entry->state;
	entry_usr.dying_time = (dying_time > jiffies) ? jiffies_to_msecs(dying_time - jiffies) : 0;

	return nlbuffer_write(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_session_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		struct request_session *request)
{
	struct nl_buffer *buffer;
	__u64 count;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending session table to userspace.");

		buffer = kmalloc(sizeof(*buffer), GFP_ATOMIC);
		if (!buffer) {
			log_err("Could not allocate an output buffer to userspace.");
			return respond_error(nl_hdr, -ENOMEM);
		}

		nlbuffer_init(buffer, nl_socket, nl_hdr);
		error = sessiondb_iterate_by_ipv4(request->l4_proto, &request->display.addr4,
				!request->display.iterate, session_entry_to_userspace, buffer);
		if (error > 0) {
			error = nlbuffer_close_continue(buffer);
		} else {
			error = nlbuffer_close(buffer);
		}

		kfree(buffer);
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

static int handle_general_config(struct nlmsghdr *nl_hdr, struct request_hdr *nat64_hdr,
		union request_general *request)
{
	struct response_general response = { .translate.mtu_plateaus = NULL };
	unsigned char *buffer;
	size_t buffer_len;
	int error;

	switch (nat64_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Returning 'General' options.");

		error = sessiondb_clone_config(&response.sessiondb);
		if (error)
			goto end;
		error = pktqueue_clone_config(&response.pktqueue);
		if (error)
			goto end;
		error = filtering_clone_config(&response.filtering);
		if (error)
			goto end;
		error = translate_clone_config(&response.translate);
		if (error)
			goto end;

		error = serialize_general_config(&response, &buffer, &buffer_len);
		if (error)
			goto end;

		error = respond_setcfg(nl_hdr, buffer, buffer_len);
		kfree(buffer);
		break;

	case OP_UPDATE:
		if (verify_superpriv(nat64_hdr))
			return respond_error(nl_hdr, -EPERM);

		log_debug("Updating 'General' options.");

		buffer = (unsigned char *) (request + 1);
		buffer_len = nat64_hdr->length - sizeof(*nat64_hdr) - sizeof(*request);

		switch (request->update.module) {
		case SESSIONDB:
			error = sessiondb_set_config(request->update.type, buffer_len, buffer);
			break;
		case PKTQUEUE:
			error = pktqueue_set_config(request->update.type, buffer_len, buffer);
			break;
		case FILTERING:
			error = filtering_set_config(request->update.type, buffer_len, buffer);
			break;
		case TRANSLATE:
			error = translate_set_config(request->update.type, buffer_len, buffer);
			break;
		default:
			log_err("Unknown module: %u", request->update.module);
			error = -EINVAL;
		}
		break;

	default:
		log_err("Unknown operation: %d", nat64_hdr->operation);
		error = -EINVAL;
	}

end:
	kfree(response.translate.mtu_plateaus);
	return respond_error(nl_hdr, error);
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
	case MODE_GENERAL:
		error = handle_general_config(nl_hdr, nat64_hdr, request);
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
