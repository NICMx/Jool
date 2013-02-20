#include "nat64/mod/config.h"
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/static_routes.h"
#include "nat64/mod/filtering_and_updating.h"
#include "nat64/mod/translate_packet.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <net/sock.h>
#include <net/netlink.h>


/**
 * Socket the userspace application will speak to. We don't use it directly, but we need the
 * reference anyway.
 */
struct sock *netlink_socket;

/**
 * A lock, used to avoid sync issues when receiving messages from userspace.
 */
DEFINE_MUTEX(my_mutex);


static bool write_data(struct response_hdr **response, enum error_code code, void *payload,
		__u32 payload_len)
{
	__u32 length = sizeof(**response) + payload_len;

	*response = kmalloc(length, GFP_ATOMIC);
	if (!(*response)) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate an answer for the user...");
		return false;
	}

	(*response)->result_code = code;
	(*response)->length = length;
	memcpy((*response) + 1, payload, payload_len);

	return true;
}

static bool write_code(struct response_hdr **response, enum error_code code)
{
	return write_data(response, code, NULL, 0);
}

static bool handle_pool6_config(__u32 operation, union request_pool6 *payload,
		struct response_hdr **as)
{
	struct ipv6_prefix *prefixes;
	__u32 prefix_count;
	enum error_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv6 pool to userspace.");

		code = pool6_to_array(&prefixes, &prefix_count);
		if (code != ERR_SUCCESS)
			return write_code(as, code);

		success = write_data(as, code, prefixes, prefix_count * sizeof(*prefixes));
		kfree(prefixes);
		return success;

	case OP_ADD:
		log_debug("Adding a prefix to the IPv6 pool.");
		return write_code(as, pool6_register(&payload->update.prefix));

	case OP_REMOVE:
		log_debug("Removing a prefix from the IPv6 pool.");
		return write_code(as, pool6_remove(&payload->update.prefix));

	default:
		return write_code(as, ERR_UNKNOWN_OP);
	}
}

static bool handle_pool4_config(__u32 operation, union request_pool4 *request,
		struct response_hdr **response)
{
	struct in_addr *entries;
	__u32 entry_count;
	enum error_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv4 pool to userspace.");

		code = pool4_to_array(&entries, &entry_count);
		if (code != ERR_SUCCESS)
			return write_code(response, code);

		success = write_data(response, code, entries, entry_count * sizeof(*entries));
		kfree(entries);
		return success;

	case OP_ADD:
		log_debug("Adding an address to the IPv4 pool.");
		return write_code(response, pool4_register(&request->update.addr));

	case OP_REMOVE:
		log_debug("Removing an address from the IPv4 pool.");
		return write_code(response, pool4_remove(&request->update.addr));

	default:
		return write_code(response, ERR_UNKNOWN_OP);
	}
}

static bool handle_bib_config(__u32 operation, union request_bib *request,
		struct response_hdr **response)
{
	struct bib_entry_us *bibs;
	__u16 bib_count;
	enum error_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending BIB to userspace.");

		code = print_bib_table(request, &bib_count, &bibs);
		if (code != ERR_SUCCESS)
			return write_code(response, code);

		success = write_data(response, code, bibs, bib_count * sizeof(*bibs));
		kfree(bibs);
		return success;

	default:
		return write_code(response, ERR_UNKNOWN_OP);
	}
}

static bool handle_session_config(__u32 operation, struct request_session *request,
		struct response_hdr **response)
{
	struct session_entry_us *sessions;
	__u16 session_count;
	enum error_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending session table to userspace.");

		code = print_session_table(request, &session_count, &sessions);
		if (code != ERR_SUCCESS)
			return write_code(response, code);

		success = write_data(response, code, sessions, session_count * sizeof(*sessions));
		kfree(sessions);
		return success;

	case OP_ADD:
		log_debug("Adding session.");
		return write_code(response, add_static_route(request));

	case OP_REMOVE:
		log_debug("Removing session.");
		return write_code(response, delete_static_route(request));

	default:
		return write_code(response, ERR_UNKNOWN_OP);
	}
}

static bool handle_filtering_config(__u32 operation, struct filtering_config *request,
		struct response_hdr **response)
{
	struct filtering_config clone;
	enum error_code code;

	if (operation == 0) {
		log_debug("Returning 'Filtering and Updating' options.");

		code = clone_filtering_config(&clone);
		if (code != ERR_SUCCESS)
			return write_code(response, code);

		return write_data(response, ERR_SUCCESS, &clone, sizeof(clone));
	} else {
		log_debug("Updating 'Filtering and Updating' options.");
		return write_code(response, set_filtering_config(operation, request));
	}
}

static bool handle_translate_config(struct request_hdr *hdr, struct translate_config *request,
		struct response_hdr **response)
{
	bool success;
	enum error_code code;

	if (hdr->operation == 0) {
		struct translate_config clone;
		unsigned char *config;
		__u16 config_len;

		log_debug("Returning 'Translate the Packet' options.");

		code = clone_translate_config(&clone);
		if (code != ERR_SUCCESS)
			return write_code(response, code);

		code = serialize_translate_config(&clone, &config, &config_len);
		if (code != ERR_SUCCESS)
			return write_code(response, code);

		success = write_data(response, ERR_SUCCESS, config, config_len);
		kfree(config);
		kfree(clone.mtu_plateaus);
		return success;
	} else {
		struct translate_config new_config;

		log_debug("Updating 'Translate the Packet' options.");

		code = deserialize_translate_config(request, hdr->length - sizeof(*hdr), &new_config);
		if (code != ERR_SUCCESS)
			return write_code(response, code);

		success = write_code(response, set_translate_config(hdr->operation, &new_config));
		kfree(new_config.mtu_plateaus);
		return success;
	}
}

/**
 * Actual configuration function. Worries nothing of Netlink, and just updates the module's
 * configuration using "mst".
 *
 * @param mst configuration update petition from userspace.
 * @param as this function's response to userspace (out parameter).
 * @return "true" if successful.
 */
bool update_nat_config(struct request_hdr *hdr, struct response_hdr **res)
{
	switch (hdr->mode) {
	case MODE_POOL6:
		return handle_pool6_config(hdr->operation, (union request_pool6 *) (hdr + 1), res);
	case MODE_POOL4:
		return handle_pool4_config(hdr->operation, (union request_pool4 *) (hdr + 1), res);
	case MODE_BIB:
		return handle_bib_config(hdr->operation, (union request_bib *) (hdr + 1), res);
	case MODE_SESSION:
		return handle_session_config(hdr->operation, (struct request_session *) (hdr + 1), res);
	case MODE_FILTERING:
		return handle_filtering_config(hdr->operation, (struct filtering_config *) (hdr + 1), res);
	case MODE_TRANSLATE:
		return handle_translate_config(hdr, (struct translate_config *) (hdr + 1), res);
	default:
		return write_code(res, ERR_UNKNOWN_MODE);
	}
}

/**
 * Gets called by "netlink_rcv_skb" when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 * @param nlh message's metadata.
 * @return result status.
 */
static int handle_netlink_message(struct sk_buff *skb_in, struct nlmsghdr *nlh)
{
	struct request_hdr *request;
	struct response_hdr *response = NULL;
	int pid, res;
	struct sk_buff *skb_out;

	if (nlh->nlmsg_type != MSG_TYPE_NAT64) {
		log_debug("Expecting %#x but got %#x.", MSG_TYPE_NAT64, nlh->nlmsg_type);
		goto failure;
	}

	request = NLMSG_DATA(nlh);
	pid = nlh->nlmsg_pid;

	if (!update_nat_config(request, &response) != 0)
		goto failure;

	skb_out = nlmsg_new(response->length, 0);
	if (!skb_out) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a response skb to the user.");
		goto failure;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, response->length, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	memcpy(nlmsg_data(nlh), response, response->length);

	res = nlmsg_unicast(netlink_socket, skb_out, pid);
	if (res < 0) {
		log_err(ERR_NETLINK, "Error code %d while returning response to the user.", res);
		goto failure;
	}

	kfree(response);
	return 0;

failure:
	kfree(response);
	return -EINVAL;
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

bool config_init(void)
{
	// Netlink sockets.
	// TODO (warning) find out what causes Osorio's compatibility issues and fix it.
	netlink_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, receive_from_userspace,
			NULL, THIS_MODULE);
	if (!netlink_socket) {
		log_err(ERR_NETLINK, "Creation of netlink socket failed.");
		return false;
	}
	log_debug("Netlink socket created.");

	return true;
}

void config_destroy(void)
{
	if (netlink_socket)
		netlink_kernel_release(netlink_socket);
}
