#include "nf_nat64_config.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <net/sock.h>
#include <net/netlink.h>

#include "nf_nat64_constants.h"
#include "nf_nat64_types.h"
#include "xt_nat64_module_comm.h"
#include "nf_nat64_pool6.h"
#include "nf_nat64_ipv4_pool.h"
#include "nf_nat64_static_routes.h"
#include "nf_nat64_translate_packet.h"


struct filtering_config filtering_conf;

/**
 * Socket the userspace application will speak to. We don't use it directly, but we need the
 * reference anyway.
 */
struct sock *my_nl_sock;

/**
 * A lock, used to avoid sync issues when receiving messages from userspace.
 */
DEFINE_MUTEX(my_mutex);


bool nat64_config_init(void)
{
//	// Netlink sockets.
//	// TODO (warning) find out what causes Osorio's compatibility issues and fix it.
//	struct netlink_kernel_cfg cfg = {
//			.input = &receive_from_userspace,
//	};
//	my_nl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
//	if (!my_nl_sock) {
//		log_warning("Creation of netlink socket failed.");
//		return false;
//	}
//	log_debug("Netlink socket created.");
//
//	return true;
}

void nat64_config_destroy(void)
{
//	if (my_nl_sock)
//		netlink_kernel_release(my_nl_sock);
}

static bool write_data(struct response_hdr **response, enum response_code code, void *payload,
		__u32 payload_len)
{
	__u32 length = sizeof(**response) + payload_len;

	*response = kmalloc(length, GFP_ATOMIC);
	if (!(*response)) {
		log_warning("Could not allocate an answer for the user...");
		return false;
	}

	(*response)->result_code = code;
	(*response)->length = length;
	memcpy((*response) + 1, payload, payload_len);

	return true;
}

static bool write_code(struct response_hdr **response, enum response_code code)
{
	return write_data(response, code, NULL, 0);
}

static bool handle_pool6_config(__u32 operation, union request_pool6 *payload,
		struct response_hdr **as)
{
	struct ipv6_prefix *prefixes;
	__u32 prefix_count;
	enum response_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv6 pool to userspace.");

		code = pool6_to_array(&prefixes, &prefix_count);
		if (code != RESPONSE_SUCCESS)
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
		return write_code(as, RESPONSE_UNKNOWN_OP);
	}
}

static bool handle_pool4_config(__u32 operation, union request_pool4 *request,
		struct response_hdr **response)
{
	struct in_addr *entries;
	__u32 entry_count;
	enum response_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending IPv4 pool to userspace.");

		code = pool4_to_array(&entries, &entry_count);
		if (code != RESPONSE_SUCCESS)
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
		return write_code(response, RESPONSE_UNKNOWN_OP);
	}
}

static bool handle_bib_config(__u32 operation, union request_bib *request,
		struct response_hdr **response)
{
	struct bib_entry_us *bibs;
	__u16 bib_count;
	enum response_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending BIB to userspace.");

		code = nat64_print_bib_table(request, &bib_count, &bibs);
		if (code != RESPONSE_SUCCESS)
			return write_code(response, code);

		success = write_data(response, code, bibs, bib_count * sizeof(*bibs));
		kfree(bibs);
		return success;

	default:
		return write_code(response, RESPONSE_UNKNOWN_OP);
	}
}

static bool handle_session_config(__u32 operation, struct request_session *request,
		struct response_hdr **response)
{
	struct session_entry_us *sessions;
	__u16 session_count;
	enum response_code code;
	bool success;

	switch (operation) {
	case OP_DISPLAY:
		log_debug("Sending session table to userspace.");

		code = nat64_print_session_table(request, &session_count, &sessions);
		if (code != RESPONSE_SUCCESS)
			return write_code(response, code);

		success = write_data(response, code, sessions, session_count * sizeof(*sessions));
		kfree(sessions);
		return success;

	case OP_ADD:
		log_debug("Adding session.");
		return write_code(response, nat64_add_static_route(request));

	case OP_REMOVE:
		log_debug("Removing session.");
		return write_code(response, nat64_delete_static_route(request));

	default:
		return write_code(response, RESPONSE_UNKNOWN_OP);
	}
}

static bool handle_filtering_config(__u32 operation, union request_filtering *request,
		struct response_hdr **response)
{
	struct filtering_config *new_config = &request->update.config;

	if (operation == 0) {
		log_debug("Returning 'Filtering and Updating' options...");
		return write_data(response, RESPONSE_SUCCESS, &filtering_conf, sizeof(filtering_conf));
	}

	log_debug("Updating 'Filtering and Updating' options:");

	if (operation & ADDRESS_DEPENDENT_FILTER_MASK)
		filtering_conf.address_dependent_filtering = new_config->address_dependent_filtering;
	if (operation & FILTER_INFO_MASK)
		filtering_conf.filter_informational_icmpv6 = new_config->filter_informational_icmpv6;
	if (operation & DROP_TCP_MASK)
		filtering_conf.drop_externally_initiated_tcp_connections =
				new_config->drop_externally_initiated_tcp_connections; // Dude.

	return write_code(response, RESPONSE_SUCCESS);
}

static bool handle_translate_config(struct request_hdr *hdr, union request_translate *request,
		struct response_hdr **response)
{
	bool success;

	if (hdr->operation == 0) {
		struct translate_config clone;
		unsigned char *config;
		__u16 config_len;

		log_debug("Returning 'Translate the Packet' options...");

		if (!clone_translate_config(&clone))
			return write_code(response, RESPONSE_ALLOC_FAILED);

		if (!serialize_translate_config(&clone, &config, &config_len))
			return write_code(response, RESPONSE_ALLOC_FAILED);

		success = write_data(response, RESPONSE_SUCCESS, config, config_len);
		kfree(config);
		kfree(clone.mtu_plateaus);
		return success;
	} else {
		struct translate_config new_config;

		log_debug("Updating 'Translate the Packet' options:");

		if (!deserialize_translate_config(request + 1, hdr->length - sizeof(*hdr), &new_config))
			return write_code(response, RESPONSE_ALLOC_FAILED);

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
		return handle_filtering_config(hdr->operation, (union request_filtering *) (hdr + 1), res);
	case MODE_TRANSLATE:
		return handle_translate_config(hdr, (union request_translate *) (hdr + 1), res);
	default:
		return write_code(res, RESPONSE_UNKNOWN_MODE);
	}
}

/**
 * Gets called by "netlink_rcv_skb" when the userspace application wants to interact with us.
 *
 * @param skb packet received from userspace.
 * @param nlh message's metadata.
 * @return result status.
 */
static int handle_netlink_message(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int pid;
	struct request_hdr *req;
	struct response_hdr *as;
	int res;
	struct sk_buff *skb_out;

	if (nlh->nlmsg_type != MSG_TYPE_NAT64) {
		log_debug("Expecting %#x but got %#x.", MSG_TYPE_NAT64, nlh->nlmsg_type);
		return -EINVAL;
	}

	req = NLMSG_DATA(nlh);
	pid = nlh->nlmsg_pid;

	if (!update_nat_config(req, &as) != 0) {
		log_warning("Error while updating NAT64 running configuration");
		return -EINVAL;
	}

	skb_out = nlmsg_new(as->length, 0);
	if (!skb_out) {
		log_warning("Failed to allocate a response skb to the user.");
		return -EINVAL;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, as->length, 0);
	NETLINK_CB(skb_out).dst_group = 0;

	memcpy(nlmsg_data(nlh), as, as->length);
	kfree(as);

	res = nlmsg_unicast(my_nl_sock, skb_out, pid);
	if (res < 0) {
		log_warning("Error code %d while returning response to the user.", res);
		return -EINVAL;
	}

	// TODO (info) as y quizá skb_out no parecen estarse liberando en todos los caminos.
	return 0;
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
