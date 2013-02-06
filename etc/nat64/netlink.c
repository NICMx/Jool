#include "netlink.h"
#include "xt_nat64_module_comm.h"

// TODO (info) En display de BIB y sesión los tres pasos se están haciendo 3 veces; no es muy práctico.
int netlink_request(void *request, __u16 request_len, int (*callback)(struct nl_msg *, void *))
{
	struct nl_sock *nls;
	int ret;

	nls = nl_socket_alloc();
	if (!nls) {
		printf("bad nl_socket_alloc\n");
		return RESPONSE_ALLOC_FAILED;
	}
	nl_socket_disable_seq_check(nls);
	nl_socket_modify_cb(nls, NL_CB_MSG_IN, NL_CB_CUSTOM, callback, NULL );
	ret = nl_connect(nls, NETLINK_USERSOCK);
	if (ret < 0) {
		nl_perror(ret, "nl_connect");
		nl_socket_free(nls);
		return RESPONSE_CONNECT_FAILED;
	}
	nl_socket_add_memberships(nls, RTNLGRP_LINK, 0);
	ret = nl_send_simple(nls, MSG_TYPE_NAT64, 0, request, request_len);
	if (ret < 0) {
		nl_perror(ret, "nl_send_simple");
		nl_close(nls);
		nl_socket_free(nls);
		return RESPONSE_SEND_FAILED;
	}

	ret = nl_recvmsgs_default(nls);
	if (ret < 0) {
		nl_perror(ret, "nl_recvmsgs_default");
	}
	nl_close(nls);
	nl_socket_free(nls);

	return RESPONSE_SUCCESS;
}
