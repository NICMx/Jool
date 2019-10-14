#include "modsocket.h"

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <sys/types.h>

#include "log.h"
#include "netsocket.h"
#include "common/config.h"
#include "common/types.h"
#include "usr/nl/jool_socket.h"

/** Receives Generic Netlink packets from the kernel module. */
static struct jool_socket jsocket;

static int validate_magic(struct request_hdr *hdr, char *sender)
{
	if (hdr->magic[0] != 'j' || hdr->magic[1] != 'o')
		goto fail;
	if (hdr->magic[2] != 'o' || hdr->magic[3] != 'l')
		goto fail;
	return 0;

fail:
	/* Well, the sender does not understand the protocol. */
	syslog(LOG_ERR, "The %s sent a message that lacks the Jool magic text.",
			sender);
	return -EINVAL;
}

static int validate_version(struct request_hdr *hdr,
		char *sender, char *receiver)
{
	__u32 hdr_version = ntohl(hdr->version);

	if (xlat_version() == hdr_version)
		return 0;

	syslog(LOG_ERR, "Version mismatch. The %s's version is %u.%u.%u.%u,\n"
			"but the %s is %u.%u.%u.%u.\n"
			"Please update the %s.",
			sender,
			hdr_version >> 24, (hdr_version >> 16) & 0xFFU,
			(hdr_version >> 8) & 0xFFU, hdr_version & 0xFFU,
			receiver,
			JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV,
			(xlat_version() > hdr_version) ? sender : receiver);
	return -EINVAL;
}

int validate_request(void *data, size_t data_len, char *sender, char *receiver)
{
	int error;

	if (data_len < sizeof(struct request_hdr)) {
		syslog(LOG_ERR, "Message from the %s is smaller than Jool's header.",
				sender);
		return -EINVAL;
	}

	error = validate_magic(data, sender);
	if (error)
		return error;

	return validate_version(data, sender, receiver);
}

void modsocket_send(void *request, size_t request_len)
{
	struct jool_result result;

	if (validate_request(request, request_len, "joold peer", "local joold"))
		return;

	/* TODO (NOW) iname */
	result = netlink_send(&jsocket, NULL, request, request_len);
	pr_result(&result);
}

static void send_ack(void)
{
	struct request_hdr hdr;
	init_request_hdr(&hdr, XT_NAT64, MODE_JOOLD, OP_ACK, false);
	modsocket_send(&hdr, sizeof(hdr));
}

/**
 * Called when joold receives data from kernelspace.
 * This data can be either sessions that should be multicasted to other joolds
 * or a response to something sent by modsocket_send().
 */
static int updated_entries_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[__ATTR_MAX + 1];
	struct request_hdr  *data;

	size_t data_size;
	char castness;
	struct jool_response response;
	struct jool_result result;

	syslog(LOG_DEBUG, "Received a packet from kernelspace.");

	result.error = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, __ATTR_MAX, NULL);
	if (result.error) {
		syslog(LOG_ERR, "genlmsg_parse() failed: %s", nl_geterror(result.error));
		return result.error;
	}

	if (!attrs[ATTR_DATA]) {
		syslog(LOG_ERR, "The request from kernelspace lacks a DATA attribute.");
		return -EINVAL;
	}

	data = nla_data(attrs[ATTR_DATA]);
	if (!data) {
		syslog(LOG_ERR, "The request from kernelspace is empty!");
		return -EINVAL;
	}
	data_size = nla_len(attrs[ATTR_DATA]);
	if (!data_size) {
		syslog(LOG_ERR, "The request from kernelspace has zero bytes.");
		return -EINVAL;
	}

	result.error = validate_request(data, data_size, "the kernel module",
			"joold daemon");
	if (result.error)
		return result.error;

	castness = data->castness;
	switch (castness) {
	case 'm':
		netsocket_send(data, data_size); /* handle request. */
		send_ack();
		return 0;
	case 'u':
		result = netlink_parse_response(data, data_size, &response);
		return pr_result(&result);
	}

	syslog(LOG_ERR, "Packet sent by the module has unknown castness: %c",
			castness);
	return -EINVAL;
}

int modsocket_setup(void)
{
	int family_mc_grp;
	struct jool_result result;

	result = netlink_setup(&jsocket, XT_NAT64);
	if (result.error)
		return pr_result(&result);

	result.error = nl_socket_modify_cb(jsocket.sk, NL_CB_VALID,
			NL_CB_CUSTOM, updated_entries_cb, NULL);
	if (result.error) {
		syslog(LOG_ERR, "Couldn't modify receiver socket's callbacks.");
		goto fail;
	}

	family_mc_grp = genl_ctrl_resolve_grp(jsocket.sk, GNL_JOOL_FAMILY,
			GNL_JOOLD_MULTICAST_GRP_NAME);
	if (family_mc_grp < 0) {
		syslog(LOG_ERR, "Unable to resolve the Netlink multicast group.");
		result.error = family_mc_grp;
		goto fail;
	}

	result.error = nl_socket_add_membership(jsocket.sk, family_mc_grp);
	if (result.error) {
		syslog(LOG_ERR, "Can't register to the Netlink multicast group.");
		goto fail;
	}

	return 0;

fail:
	netlink_teardown(&jsocket);
	syslog(LOG_ERR, "Netlink error message: %s", nl_geterror(result.error));
	return result.error;
}

void modsocket_teardown(void)
{
	netlink_teardown(&jsocket);
}

void *modsocket_listen(void *arg)
{
	int error;

	do {
		error = nl_recvmsgs_default(jsocket.sk);
		if (error < 0) {
			syslog(LOG_ERR, "Error receiving packet from kernelspace: %s",
					nl_geterror(error));
		}
	} while (true);

	return 0;
}
