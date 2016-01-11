#include <stdbool.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <errno.h>
#include <unistd.h>


#include "nat64/common/genetlink.h"
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

static int fail(int error, char *func_name)
{
	printf("%s() failed.\n", func_name);
	return error;
}

static int nl_fail(int error, char *func_name)
{
	printf("%s (%d)\n", nl_geterror(error), error);
	return fail(error, func_name);
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nlerr,
		void *arg)
{

	fprintf(stderr, "error handler\n");

	fprintf(stderr, "Error: %s", ((char*) nlerr) + sizeof(*nlerr));
	fprintf(stderr, "(Error code: %d)\n", nlerr->error);
	error_handler_called = true;
	return -abs(nlerr->error);

}

static int netlink_msg_handler(struct nl_msg * msg, void * arg)
{
	struct nl_core_buffer *buffer;

	struct nlmsghdr *nl_hdr;
	struct nlattr *attrs[__ATTR_MAX + 1];
	char * error_msg;
	int error = 0;

	nl_hdr = nlmsg_hdr(msg);

	fprintf(stderr, "handling jool message!\n");

	fprintf(stderr, "attribute count: %u \n", sizeof(attrs) / sizeof(*attrs));

	error = genlmsg_parse(nl_hdr, 0, attrs, __ATTR_MAX, NULL);

	if (error) {
		printf("%s (%d)\n", nl_geterror(error), error);
		printf("genlmsg_parse failed. \n");
		return error;
	}

	if (attrs[1]) {
		buffer = (struct nl_core_buffer *)nla_data(attrs[1]);
	} else {
		printf("null buffer!\n");
		return 0;
	}

	if (buffer->error_code < 0) {

		if (buffer->len > 0) {

			error_msg = malloc(sizeof(char) * buffer->len + 1);
			error_msg[buffer->len] = '\0';
			memcpy(error_msg, (buffer+1), sizeof(char) * buffer->len);
			fprintf(stderr, "Jool Error: %s", error_msg);
			free(error_msg);

		}

		fprintf(stderr, "(Error code: %d)\n", buffer->error_code);

	} else {

		if (response_callback != NULL) {
			fprintf(stderr, "calling response callback!!\n");
			return response_callback(buffer, arg);
		} else {
			fprintf(stderr, "response callback is null!!\n");
		}
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
	char *error_function;

	sk = nl_socket_alloc();
	if (!sk)
		return fail(-ENOMEM, "nl_socket_alloc");

	nl_socket_disable_seq_check(sk);

	error = nl_socket_modify_err_cb(sk, NL_CB_CUSTOM , error_handler, NULL);

	if (error) {
		error_function = "nl_socket_modify_err_cb";
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
			goto fail;
	}

	return 0;

	fail:
	nl_socket_free(sk);
	return nl_fail(error, error_function);
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


int genetlink_send_msg(void *request,
		__u32 request_len, void *cb_arg)
{

	char *error_function;
	void *payload;
	struct nl_msg *msg;

	int error;
	int i;


	msg = nlmsg_alloc();

	if (!msg) {
		error = -1;
		error_function = "nlmsg_alloc";

		goto fail;
	}


	payload = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,0, 0, JOOL_COMMAND, 1);

	if (!payload) {
		error = -1;
		error_function = "genlmsg_put";
		goto fail;
	}

	error = nla_put(msg, ATTR_DATA, (int)request_len, request);

	if (error) {
		error_function = "nla_put";
		goto fail;
	}

	error = nl_send_auto(sk, msg);

	if (error < 0) {
		error_function = "nl_send_auto_complete";
		goto fail;
	}

	for (i = 0; i < (sizeof(callbacks) / sizeof(callbacks[0])); i++) {

		error = nl_socket_modify_cb(sk, callbacks[i], NL_CB_CUSTOM, netlink_msg_handler, cb_arg);

		if (error < 0) {
			log_err(
					"Could not register response handler. " "I won't be able to parse Jool's response, so I won't send the request.\n" "Netlink error message: %s (Code %d)",
					nl_geterror(error), error);

			return error;
		}
	}

	if (error) {
		error_function = "nl_socket_modify_cb";
		goto fail;
	}

	error = nl_recvmsgs_default(sk);

	if (error < 0) {
		error_function = "nl_recvmsgs_default";
		goto fail;
	}

	nlmsg_free(msg);

	return 0;

	fail:
	return nl_fail(error, error_function);
}

int netlink_request(void *request, __u32 request_len,
		int (*cb)(struct nl_core_buffer *, void *), void *cb_arg)
{
	response_callback = cb;

	return genetlink_send_msg(request, request_len, cb_arg);
}

int netlink_init(void)
{
	int error = 0;

	error = prepare_socket();

	return error;
}

void netlink_destroy(void)
{
	nl_close(sk);
	nl_socket_free(sk);
}
