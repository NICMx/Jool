#include "netlink.h"
#include "xt_nat64_module_comm.h"

struct nl_sock *nl_socket;

error_t netlink_connect(int (*callback)(struct nl_msg *, void *))
{
	int ret;

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
		return RESPONSE_SEND_FAILED;
	}

	ret = nl_connect(nl_socket, NETLINK_USERSOCK);
	if (ret < 0) {
		nl_perror(ret, "Could not connect to the NAT64 (is it really up?)");
		goto connect_failure;
	}

	return RESPONSE_SUCCESS;

connect_failure:
	nl_socket_free(nl_socket);
	return RESPONSE_CONNECT_FAILED;
}

error_t netlink_request(void *request, __u16 request_len)
{
	int ret;

	ret = nl_send_simple(nl_socket, MSG_TYPE_NAT64, 0, request, request_len);
	if (ret < 0) {
		nl_perror(ret, "Error while messaging the NAT64");
		return RESPONSE_SEND_FAILED;
	}

	ret = nl_recvmsgs_default(nl_socket);
	if (ret < 0) {
		nl_perror(ret, "Waiting for the NAT64's response yielded failure");
		return RESPONSE_SEND_FAILED;
	}

	return RESPONSE_SUCCESS;
}

void netlink_disconnect(void)
{
	nl_close(nl_socket);
	nl_socket_free(nl_socket);
}

error_t netlink_single_request(void *request, __u16 request_len,
		int (*callback)(struct nl_msg *, void *))
{
	error_t result;

	result = netlink_connect(callback);
	if (result != RESPONSE_SUCCESS)
		return result;
	result = netlink_request(request, request_len);
	netlink_disconnect();

	return result;
}
