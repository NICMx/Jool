#include "netlink.h"
#include <errno.h>
#include "types.h"

int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg) {

	log_err("this is the message length: %d", nlerr->msg->nlmsg_len) ;

	return 0;
}

int netlink_request(void *request, __u16 request_len,
		int (*cb)(struct nl_msg *, void *), void *cb_arg)
{
	struct nl_sock *sk;
	enum nl_cb_type callbacks[] = { NL_CB_VALID, NL_CB_FINISH, NL_CB_ACK };
	int i;
	int error;

	sk = nl_socket_alloc();
	if (!sk) {
		log_err("Could not allocate a socket.");
		return -ENOMEM;
	}

	for (i = 0; i < (sizeof(callbacks) / sizeof(callbacks[0])); i++) {
		error = nl_socket_modify_cb(sk, callbacks[i], NL_CB_CUSTOM, cb, cb_arg);
		if (error < 0) {
			log_err("Could not register response handler. "
					"Netlink error message: %s (Code %d)", nl_geterror(error),
					error);
			goto fail_free;
		}
	}

	error = nl_connect(sk, NETLINK_USERSOCK);
	if (error < 0) {
		log_err("Could not bind the socket. Netlink error msg: %s (Code %d)",
				nl_geterror(error), error);
		goto fail_free;
	}

	error = nl_send_simple(sk, MSG_TYPE_GRAYBOX, 0, request, request_len);
	if (error < 0) {
		log_err("Could not send the request (is the module really up?).\n"
				"Netlink error message: %s (Code %d)", nl_geterror(error),
				error);
		goto fail_close;
	}

	error = nl_recvmsgs_default(sk);
	if (error < 0) {
		log_err("%s (System error %d)", nl_geterror(error), error);
		goto fail_close;
	}

	nl_close(sk);
	nl_socket_free(sk);
	return 0;

fail_close:
	nl_close(sk);
	/* Fall through. */

fail_free:
	nl_socket_free(sk);
	return -EINVAL;
}
