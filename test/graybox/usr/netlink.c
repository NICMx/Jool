#include "netlink.h"

#include <errno.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include "nat64/common/types.h"

static struct nl_sock *sk;
static int family;

int nlsocket_init(char *family_name)
{
	int error;

	sk = nl_socket_alloc();
	if (!sk) {
		log_err("Could not allocate the socket to kernelspace.");
		log_err("(I guess we're out of memory.)");
		return -1;
	}

	/* TODO there was a comment here. */
	nl_socket_disable_auto_ack(sk);

	error = genl_connect(sk);
	if (error) {
		log_err("Could not open the socket to kernelspace.");
		goto fail;
	}

	family = genl_ctrl_resolve(sk, family_name);
	if (family < 0) {
		log_err("Jool's socket family doesn't seem to exist.");
		log_err("(This probably means Jool hasn't been modprobed.)");
		error = family;
		goto fail;
	}

	return 0;

fail:
	nl_socket_free(sk);
	return netlink_print_error(error);
}

void nlsocket_destroy()
{
	nl_socket_free(sk);
}

int nlsocket_create_msg(int cmd, struct nl_msg **result)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg) {
		log_err("Out of memory!");
		return -ENOMEM;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0, cmd, 1)) {
		log_err("Unknown error building the packet to the kernel.");
		nlmsg_free(msg);
		return -EINVAL;
	}

	return 0;
}

int nlsocket_send(struct nl_msg *msg)
{
	int error;

	error = nl_send_auto(sk, msg);
	if (error < 0) {
		log_err("Could not dispatch the request to kernelspace.");
		return netlink_print_error(error);
	}

	return 0;
}

int netlink_print_error(int error)
{
	log_err("Netlink error %d: %s", error, nl_geterror(error));
	return error;
}
