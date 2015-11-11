#include "nat64/usr/netlink.h"
#include "nat64/common/config.h"
#include "nat64/usr/types.h"
#include <errno.h>
#include <unistd.h>

#define HDR_LEN sizeof(struct request_hdr)

/*
 * This will need to be refactored if some day we need multiple request calls
 * in separate threads.
 * At this point this is the best I can do because there's no other way to tell
 * whether the error returned by nl_recvmsgs_default() is a Netlink error or a
 * Jool error.
 */
bool error_handler_called = false;

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg)
{
	fprintf(stderr,"Error: %s", ((char*)nlerr)+sizeof(*nlerr));
	fprintf(stderr,"(Error code: %d)\n", nlerr->error);
	error_handler_called = true;
	return -abs(nlerr->error);
}

/*
 * TODO (performance) we're creating a separate nl connection for every request.
 * Some of Jool's requests (--display commands in particular) could be grouped into a single
 * connection.
 */
int netlink_request(void *request, __u16 request_len, int (*cb)(struct nl_msg *, void *),
		void *cb_arg)
{
	struct nl_sock *sk;
	enum nl_cb_type callbacks[] = { NL_CB_VALID, NL_CB_FINISH, NL_CB_ACK };
	int i;
	int error;

	sk = nl_socket_alloc();
	if (!sk) {
		log_err("Could not allocate a socket; cannot speak to the NAT64.");
		return -ENOMEM;
	}

	for (i = 0; i < (sizeof(callbacks) / sizeof(callbacks[0])); i++) {
		error = nl_socket_modify_cb(sk, callbacks[i], NL_CB_CUSTOM, cb, cb_arg);
		if (error < 0) {
			log_err("Could not register response handler. "
					"I won't be able to parse Jool's response, so I won't send the request.\n"
					"Netlink error message: %s (Code %d)", nl_geterror(error), error);
			goto fail_free;
		}
	}

	error = nl_socket_modify_err_cb(sk,NL_CB_CUSTOM,error_handler,cb_arg) ;

	if (error < 0) {
		log_err("Could not register error handler. "
				"I won't be able to parse Jool's response errors, so I won't send the request.\n"
				"Netlink error message: %s (Code %d)", nl_geterror(error),error) ;
			goto fail_free;
	}


	error = nl_connect(sk, NETLINK_USERSOCK);
	if (error < 0) {
		log_err("Could not bind the socket to Jool.\n"
				"Netlink error message: %s (Code %d)", nl_geterror(error), error);
		goto fail_free;
	}

	error = nl_send_simple(sk, MSG_TYPE_JOOL, 0, request, request_len);
	if (error < 0) {
		log_err("Could not send the request to Jool (is it really up?).\n"
				"Netlink error message: %s (Code %d)", nl_geterror(error), error);
		goto fail_close;
	}

	error = nl_recvmsgs_default(sk);
	if (error < 0) {
		if (!error_handler_called)
			log_err("Netlink error message: %s (Code %d)", nl_geterror(error), error);
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
