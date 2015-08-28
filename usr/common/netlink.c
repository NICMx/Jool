#include "nat64/usr/netlink.h"
#include "nat64/common/config.h"
#include "nat64/usr/types.h"
#include <errno.h>
#include <unistd.h>



static struct nl_sock *sk;
static enum nl_cb_type callbacks[] = { NL_CB_VALID, NL_CB_FINISH, NL_CB_ACK };

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

int netlink_init_multipart_connection(int (*cb)(struct nl_msg *, void *),void *cb_arg)
{
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
			 nl_socket_free(sk);
			 return -EINVAL;
		}
	}

	error = nl_connect(sk, NETLINK_USERSOCK);
	if (error < 0) {
		log_err("Could not bind the socket to Jool.\n"
				"Netlink error message: %s (Code %d)", nl_geterror(error), error);
		 nl_close(sk);
		 nl_socket_free(sk);
		 return -EINVAL;
	}

   return 0;
}


int netlink_request_multipart(void *request, __u16 request_len,	enum config_mode mode, enum config_operation operation)
{

    int error;

	__u8 request_container[sizeof(struct request_hdr) + request_len];
	struct request_hdr *hdr = (struct request_hdr *) request_container;

    if(!sk)
    {
      log_info("socket not initialized!!");
    }

	init_request_hdr(hdr, sizeof(request_container), mode, operation) ;
	memcpy(hdr + 1, request, request_len);

	error = nl_send_simple(sk, MSG_TYPE_JOOL, NLM_F_MULTI,
			request_container,
			sizeof(struct request_hdr) + request_len) ;

	if (error < 0) {
		log_err("Could not send the request to Jool (is it really up?).\n"
				"Netlink error message: %s (Code %d)",
				nl_geterror(error), error) ;

		goto fail_close;
	}

	error = nl_recvmsgs_default(sk);
	if (error < 0) {
		log_err("%s (System error %d)", nl_geterror(error), error);
		goto fail_close;
	}


	return 0;

   fail_close:
	 nl_close(sk);
	 nl_socket_free(sk);

	 return -EINVAL;

}

int netlink_request_multipart_done()
{

	int error;

	unsigned char request_container[sizeof(struct request_hdr)];
	struct request_hdr *hdr = (struct request_hdr *) request_container;

	init_request_hdr(hdr, sizeof(request_container),NLMSG_DONE, 0) ;
	error = nl_send_simple(sk, NLMSG_DONE,0, request_container,sizeof(request_container));

	nl_close(sk);
	nl_socket_free(sk);
	return 0;

//fail_close:
//	nl_close(sk);
//	/* Fall through. */
//
//fail_free:
//	nl_socket_free(sk);
//	return -EINVAL;
}

void netlink_request_multipart_close(void)
{
	nl_close(sk);
	if(sk)
	nl_socket_free(sk);
}
