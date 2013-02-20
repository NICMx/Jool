#include "nat64/usr/netlink.h"
#include "nat64/comm/config_proto.h"
#include <errno.h>


int netlink_request(void *request, __u16 request_len, int (*callback)(struct nl_msg *, void *))
{
	struct nl_sock *nl_socket;
	int ret;

	nl_socket = nl_socket_alloc();
	if (!nl_socket) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate a socket; cannot speak to the NAT64.");
		return ENOMEM;
	}

	// Warning shutupper. I'm not sure if this is the correct way to handle it.
	nl_socket_disable_seq_check(nl_socket);

	ret = nl_socket_modify_cb(nl_socket, NL_CB_MSG_IN, NL_CB_CUSTOM, callback, NULL);
	if (ret < 0) {
		log_err(ERR_NETLINK, "Could not register response handler. I won't be able to "
				"parse the NAT64's response, so I won't send the request.\n"
				"Netlink error message: %s (Code %d)", nl_geterror(ret), ret);
		goto fail_free;
	}

	ret = nl_connect(nl_socket, NETLINK_USERSOCK);
	if (ret < 0) {
		log_err(ERR_NETLINK, "Could not connect to the NAT64.\n"
				"Netlink error message: %s (Code %d)", nl_geterror(ret), ret);
		goto fail_free;
	}

	ret = nl_send_simple(nl_socket, MSG_TYPE_NAT64, 0, request, request_len);
	if (ret < 0) {
		log_err(ERR_NETLINK, "Could not send the request to the NAT64 (is it really up?).\n"
				"Netlink error message: %s (Code %d)", nl_geterror(ret), ret);
		goto fail_close;
	}

	ret = nl_recvmsgs_default(nl_socket);
	if (ret < 0) {
		log_err(ERR_NETLINK, "Waiting for the NAT64's response yielded failure.\n"
				"Netlink error message: %s (Code %d)", nl_geterror(ret), ret);
		goto fail_close;
	}

	nl_close(nl_socket);
	nl_socket_free(nl_socket);
	return 0;

fail_close:
	nl_close(nl_socket);
	/* Fall through. */

fail_free:
	nl_socket_free(nl_socket);
	return EINVAL;
}
