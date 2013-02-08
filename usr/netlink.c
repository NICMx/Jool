#include "nat64/netlink.h"
#include "nat64/config_proto.h"


error_t netlink_request(void *request, __u16 request_len, int (*callback)(struct nl_msg *, void *))
{
	int ret;
	struct nl_sock *nl_socket;

	nl_socket = nl_socket_alloc();
	if (!nl_socket) {
		printf("Error: Could not allocate a socket; cannot speak to the NAT64");
		return RESPONSE_ALLOC_FAILED;
	}

	// Warning shutupper. I'm not sure if this is the correct way to handle it.
	nl_socket_disable_seq_check(nl_socket);

	ret = nl_socket_modify_cb(nl_socket, NL_CB_MSG_IN, NL_CB_CUSTOM, callback, NULL );
	if (ret < 0) {
		nl_perror(ret, "Could not register response handler. I will not be able to parse the "
				"NAT64's response, so I will not send the request");
		goto fail_free;
	}

	ret = nl_connect(nl_socket, NETLINK_USERSOCK);
	if (ret < 0) {
		nl_perror(ret, "Could not connect to the NAT64 (is it really up?)");
		goto fail_free;
	}

	ret = nl_send_simple(nl_socket, MSG_TYPE_NAT64, 0, request, request_len);
	if (ret < 0) {
		nl_perror(ret, "Error while messaging the NAT64");
		goto fail_close;
	}

	ret = nl_recvmsgs_default(nl_socket);
	if (ret < 0) {
		nl_perror(ret, "Waiting for the NAT64's response yielded failure");
		goto fail_close;
	}

	nl_close(nl_socket);
	nl_socket_free(nl_socket);
	return RESPONSE_SUCCESS;

fail_close:
	nl_close(nl_socket);
	/* Fall through. */

fail_free:
	nl_socket_free(nl_socket);
	return RESPONSE_SEND_FAILED;
}
