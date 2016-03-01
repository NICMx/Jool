#include "nat64/usr/joold/modsocket.h"

#include <errno.h>
#include <string.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <sys/types.h>
#include "nat64/common/config.h"
#include "nat64/common/genetlink.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/usr/netlink.h"
#include "nat64/usr/types.h"
#include "nat64/usr/joold/hdr.h"
#include "nat64/usr/joold/netsocket.h"

/** Receives Generic Netlink packets from the kernel module. */
static struct nl_sock *sk;
int family;

/* TODO (duplicate code) */
static int print_error_msg(struct jool_response *response)
{
	char *msg;

	if (response->payload_len <= 0) {
		log_err("Error (The kernel's response is empty so the cause is unknown.)");
		goto end;
	}

	msg = response->payload;
	if (msg[response->payload_len - 1] != '\0') {
		log_err("Error (The kernel's response is not a string so the cause is unknown.)");
		goto end;
	}

	log_err("Jool Error: %s", msg);
	/* Fall through. */

end:
	log_err("(Error code: %u)", response->hdr->error_code);
	return response->hdr->error_code;
}

/* TODO (duplicate code) */
int handle_response(void *data, size_t data_len, char *sender)
{
	struct jool_response response;

	if (data_len < sizeof(struct response_hdr)) {
		log_err("The module's response is too small to contain a response header.");
		return -EINVAL;
	}

	response.hdr = data;
	response.payload = response.hdr + 1;
	response.payload_len = data_len - sizeof(struct response_hdr);

	return response.hdr->error_code ? print_error_msg(&response) : 0;
}

/**
 * Called when joold receives data from kernelspace.
 * This data can be either sessions that should be multicasted to other joolds
 * or a response to something sent by modsocket_send().
 */
static int updated_entries_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[__ATTR_MAX + 1];
	struct request_hdr *data;
	size_t data_size;
	char castness;
	int error;

	log_info("Received a packet from kernelspace.");

	error = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, __ATTR_MAX, NULL);
	if (error) {
		log_err("genlmsg_parse() failed: %s", nl_geterror(error));
		return error;
	}

	if (!attrs[ATTR_DATA]) {
		log_err("The request from kernelspace lacks a DATA attribute.");
		return -EINVAL;
	}
	data = nla_data(attrs[ATTR_DATA]);
	if (!data) {
		log_err("The request from kernelspace is empty!");
		return -EINVAL;
	}
	data_size = nla_len(attrs[ATTR_DATA]);
	if (!data_size) {
		log_err("The request from kernelspace has zero bytes.");
		return -EINVAL;
	}

	error = validate_header(data, data_size, "the kernel module");
	if (error)
		return error;

	castness = ((struct request_hdr *)data)->castness;
	switch (castness) {
	case 'm':
		netsocket_send(data, data_size); /* handle request. */
		return 0;
	case 'u':
		return handle_response(data, data_size, "the kernel module");
	}

	log_err("Packet sent by the module has unknown castness: %c", castness);
	return -EINVAL;
}

int modsocket_init(void)
{
	int family_mc_grp;
	int error;

	sk = nl_socket_alloc();
	if (!sk) {
		log_err("Could not allocate the socket to kernelspace.");
		log_err("(I guess we're out of memory.)");
		return -1;
	}

	/*
	 * ACKs are only going to slow us down.
	 * We use UDP in the network, so we're assuming best-effort anyway.
	 */
	nl_socket_disable_auto_ack(sk);

	error = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
			updated_entries_cb, NULL);
	if (error) {
		log_err("Couldn't modify receiver socket's callbacks.");
		goto fail;
	}

	error = genl_connect(sk);
	if (error) {
		log_err("Could not open the socket to kernelspace.");
		goto fail;
	}

	family = genl_ctrl_resolve(sk, GNL_JOOL_FAMILY_NAME);
	if (family < 0) {
		log_err("Jool's socket family doesn't seem to exist.");
		log_err("(This probably means Jool hasn't been modprobed.)");
		error = family;
		goto fail;
	}

	family_mc_grp = genl_ctrl_resolve_grp(sk, GNL_JOOL_FAMILY_NAME,
			GNL_JOOLD_MULTICAST_GRP_NAME);
	if (family_mc_grp < 0) {
		log_err("Unable to resolve the Netlink multicast group.");
		error = family_mc_grp;
		goto fail;
	}

	error = nl_socket_add_membership(sk, family_mc_grp);
	if (error) {
		log_err("Can't register to the Netlink multicast group.");
		goto fail;
	}

	return 0;

fail:
	nl_socket_free(sk);
	return netlink_print_error(error);
}

void modsocket_destroy(void)
{
	nl_socket_free(sk);
}

void *modsocket_listen(void *arg)
{
	int error;

	do {
		error = nl_recvmsgs_default(sk);
		if (error < 0) {
			log_err("Error receiving packet from kernelspace: %s",
					nl_geterror(error));
		}
	} while (true);

	return 0;
}

/* TODO (duplicate code) this is a ripoff of netlink_request_simple(). */
void modsocket_send(void *request, size_t request_len)
{
	struct nl_msg *msg;
	int error;

	error = validate_header(request, request_len, "a joold peer");
	if (error)
		return;

	msg = nlmsg_alloc();
	if (!msg) {
		log_err("Could not allocate the request to kernelspace.");
		log_err("(I guess we're out of memory.)");
		return;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
			JOOL_COMMAND, 1)) {
		log_err("Unknown error building the packet to the kernel.");
		nlmsg_free(msg);
		return;
	}

	error = nla_put(msg, ATTR_DATA, request_len, request);
	if (error) {
		log_err("Could not write on the packet to kernelspace.");
		netlink_print_error(error);
		nlmsg_free(msg);
		return;
	}

	log_info("Sending %zu bytes to the kernel.", request_len);
	error = nl_send_auto(sk, msg);
	if (error < 0) {
		log_err("Could not dispatch the request to kernelspace.");
		netlink_print_error(error);
		/* Fall through. */
	}

	nlmsg_free(msg);
}
