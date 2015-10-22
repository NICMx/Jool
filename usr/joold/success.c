#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include "nat64/common/constants.h"
#include "nat64/common/joold/joold_config.h"
#include "nat64/usr/types.h"

static int cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr;
	char *buffer;
	unsigned int buffer_len;

	hdr = nlmsg_hdr(msg);
	buffer = nlmsg_data(hdr);
	buffer_len = nlmsg_datalen(hdr);

	log_info("len:%u buffer:%s", buffer_len, buffer);

	return 0;
}

int main(int argc, char **argv)
{
	struct nl_sock *sk;
	int error;

	sk = nl_socket_alloc();
	if (!sk) {
		log_err("Couldn't allocate the netlink receiver socket.");
		return -1;
	}

	nl_socket_disable_seq_check(sk);

	error = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, cb, NULL);
	if (error) {
		log_err("Couldn't modify the receiver socket's callback.");
		goto fail;
	}

	error = nl_connect(sk, NETLINK_MULTICAST_FAMILY);
	if (error) {
		log_err("Couldn't connect the receiver socket to the kernel.");
		log_err("This is likely because Jool isn't active and "
				"therefore it hasn't registered the protocol.");
		goto fail;
	}

	error = nl_socket_add_memberships(sk, JOOLD_MULTICAST_GROUP, 0);
	if (error) {
		log_err("Couldn't add membership to the multicast group.");
		goto fail;
	}

	log_info("Ok, listening.");
	error = nl_recvmsgs_default(sk);
	log_info("Error code: %d", error);

	nl_close(sk);

	return 0;

fail:
	log_err("%s (error code %d)", nl_geterror(error), error);
	return error;
}
