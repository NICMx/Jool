#include <stdbool.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <errno.h>
#include <unistd.h>

#include "nat64/common/genetlink.h"
#include "nat64/usr/netlink.h"
#include "nat64/common/config.h"
#include "nat64/usr/types.h"

static struct nl_sock *sk;
static int family;

static enum nl_cb_type callbacks[] = { NL_CB_VALID, NL_CB_FINISH, NL_CB_ACK };

/*
 * This will need to be refactored if some day we need multiple request calls
 * in separate threads.
 * At this point this is the best I can do because there's no other way to tell
 * whether the error returned by nl_recvmsgs_default() is a Netlink error or a
 * Jool error.
 *
 * TODO might need to apply #184 to the new code.
 */
bool error_handler_called = false;

static int (*response_callback)(struct nl_core_buffer *, void *);

static int fail(int error, char *func_name) {
	printf("%s() failed.\n", func_name);
	return error;
}

static int nl_fail(int error, char *func_name) {
	printf("%s (%d)\n", nl_geterror(error), error);
	return fail(error, func_name);
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nlerr,
		void *arg) {

	fprintf(stderr, "error handler\n");

	fprintf(stderr, "Error: %s", ((char*) nlerr) + sizeof(*nlerr));
	fprintf(stderr, "(Error code: %d)\n", nlerr->error);
	error_handler_called = true;
	return -abs(nlerr->error);

}

static int netlink_msg_handler(struct nl_msg * msg, void * arg)
{
	struct nl_core_buffer *buffer = genlmsg_data(nlmsg_data(nlmsg_hdr(msg)));

	fprintf(stderr, "nl_msg len -> %d\n", nlmsg_datalen(nlmsg_hdr(msg)));

	if (buffer->error_code < 0) {

		if (buffer->len > 0)
			fprintf(stderr, "Jool Error: %s", (char *)(buffer+1));

		fprintf(stderr, "(Error code: %d)\n", buffer->error_code);

	} else {
		return response_callback(buffer, arg);
	}

	return 0;
}

void * netlink_get_data(struct nl_core_buffer *buffer)
{
	return buffer + 1;
}

static int prepare_socket(void)
{
	int error;

	sk = nl_socket_alloc();
	if (!sk)
		return fail(-ENOMEM, "nl_socket_alloc");

	nl_socket_disable_seq_check(sk);

	error = nl_socket_modify_err_cb(sk, NL_CB_CUSTOM, error_handler, NULL);

	if (error) {
		nl_socket_free(sk);
		return -EINVAL;
	}

	return 0;
}

int netlink_init_multipart_connection(int (*cb)(struct nl_msg *, void *),
		void *cb_arg)
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
			log_err(
					"Could not register response handler. " "I won't be able to parse Jool's response, so I won't send the request.\n" "Netlink error message: %s (Code %d)",
					nl_geterror(error), error);
			nl_socket_free(sk);
			return -EINVAL;
		}
	}

	error = nl_connect(sk, NETLINK_USERSOCK);
	if (error < 0) {
		log_err(
				"Could not bind the socket to Jool.\n" "Netlink error message: %s (Code %d)",
				nl_geterror(error), error);
		nl_close(sk);
		nl_socket_free(sk);
		return -EINVAL;
	}

	return 0;
}

int netlink_request_multipart(void *request, __u16 request_len,
		enum config_mode mode, enum config_operation operation)
{

	int error;

	__u8 request_container[sizeof(struct request_hdr) + request_len];
	struct request_hdr *hdr = (struct request_hdr *) request_container;

	if (!sk) {
		log_info("socket not initialized!!");
	}

	init_request_hdr(hdr, sizeof(request_container), mode, operation);
	memcpy(hdr + 1, request, request_len);

	error = nl_send_simple(sk, MSG_TYPE_JOOL, NLM_F_MULTI, request_container,
			sizeof(struct request_hdr) + request_len);

	if (error < 0) {
		log_err("Could not send the request to Jool (is it really up?).\n"
				"Netlink error message: %s (Code %d)",
				nl_geterror(error), error);

		goto fail_close;
	}

	error = nl_recvmsgs_default(sk);
	if (error < 0) {
		log_err("%s (System error %d)", nl_geterror(error), error);
		goto fail_close;
	}

	return 0;

	fail_close: nl_close(sk);
	nl_socket_free(sk);

	return -EINVAL;

}

int netlink_request_multipart_done(void)
{
	unsigned char request_container[sizeof(struct request_hdr)];
	struct request_hdr *hdr = (struct request_hdr *) request_container;
	int error;

	init_request_hdr(hdr, sizeof(request_container), NLMSG_DONE, 0);
	error = nl_send_simple(sk, NLMSG_DONE, 0, request_container,
			sizeof(request_container));

	nl_close(sk);
	nl_socket_free(sk);
	return error;
}

void netlink_request_multipart_close(void)
{
	nl_close(sk);
	if (sk)
		nl_socket_free(sk);
}

int genetlink_send_msg(struct request_hdr *usr_hdr, void *request,
		__u16 request_len, void *cb_arg)
{

	char *error_function;
	void *payload;
	struct nl_msg *msg;

	int error;

	error = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, netlink_msg_handler, cb_arg);
	if (error) {
		error_function = "nl_socket_modify_cb";
		goto fail;
	}

	error = genl_connect(sk);
	if (error) {
		error_function = "genl_connect";
		goto fail;
	}

	family = genl_ctrl_resolve(sk, GNL_JOOL_FAMILY_NAME);
	if (family < 0) {
		error = family;
		error_function = "genl_ctrl_resolve";
		printf("(remember the kernel module needs to register the "
				"family before we can use it.)\n");
		goto fail_close;
	}

	msg = nlmsg_alloc();

	if (!msg) {
		error = -1;
		error_function = "nlmsg_alloc";

		goto fail_close;
	}

	payload = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			sizeof(*usr_hdr), 0, JOOL_COMMAND, 1);

	if (!payload) {
		error = -1;
		error_function = "genlmsg_put";
		goto fail_close;
	}

	/** We add jool's user header in the section specified as user header by generic netlink specification.
	 * Before doing this, we had to reserve space for jool's header, passing sizeof(*usr_hdr) as argument in the fuction genlmsg_put called above.
	 */
	memcpy(payload, usr_hdr, sizeof(*usr_hdr));
	payload += sizeof(*usr_hdr);

	memcpy(payload, request, request_len);

	error = nl_send_auto(sk, msg);
	if (error < 0) {
		error_function = "nl_send_auto";
		goto fail_close;
	}

	nl_recvmsgs_default(sk);

	return 0;

	fail_close: nl_close(sk);

	fail:
	return nl_fail(error, error_function);
}

int netlink_request(void *request, __u16 request_len,
		int (*cb)(struct nl_core_buffer *, void *), void *cb_arg)
{

	struct request_hdr *usr_hdr = (struct request_hdr *)request;
	//void * data = usr_hdr + 1;

	response_callback = cb;

	printf("sending message");

	return genetlink_send_msg(usr_hdr, request, request_len, cb_arg);

}



int netlink_init(void)
{

	int error = 0;

	error = prepare_socket();

	return error;

}
