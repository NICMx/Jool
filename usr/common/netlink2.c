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
#include "nat64/usr/types.h"

static struct nl_sock *sk;
static int family;

static enum nl_cb_type callbacks[] = {
		NL_CB_MSG_IN,
	};

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
			return response_callback(buffer, arg);
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


	nl_socket_disable_auto_ack(sk);

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

int genetlink_send_msg(void *request,
		__u32 request_len, void *cb_arg)
{

	char *error_function;
	void *payload;
	struct nl_msg *msg;

	int error;
	int i;

	for (i = 0; i < (sizeof(callbacks) / sizeof(callbacks[0])); i++) {

		error = nl_socket_modify_cb(sk, callbacks[i], NL_CB_CUSTOM, netlink_msg_handler, cb_arg);

		if (error < 0) {
			log_err("Could not register response handler. " "I won't be able to parse Jool's response, so I won't send the request.\n" "Netlink error message: %s (Code %d)",
					nl_geterror(error), error);

			return error;
		}
	}

	msg = nlmsg_alloc();

	if (!msg) {
		error = -1;
		error_function = "nlmsg_alloc";

		goto fail2;
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
		error_function = "nl_send_auto";
		goto fail;
	}

	nl_recvmsgs_default(sk);

	if (error < 0) {
		error_function = "nl_recvmsgs_default";
		goto fail;
	}

	nlmsg_free(msg);

	return 0;

	fail:
	nlmsg_free(msg);
	fail2:
	return nl_fail(error, error_function);
}

int netlink_request(void *request, __u32 request_len,
		int (*cb)(struct nl_core_buffer *, void *), void *cb_arg)
{
	response_callback = cb;

	int error = genetlink_send_msg(request, request_len, cb_arg);

	return error;
}

int netlink_simple_request(void *request, __u32 request_len) {

	char *error_function;
	void *payload;
	struct nl_msg *msg;

	int error;

	msg = nlmsg_alloc();

	if (!msg) {
		error = -1;
		error_function = "nlmsg_alloc";

		goto fail2;
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
		error_function = "nl_send_auto";
		goto fail;
	}

	nlmsg_free(msg);
	return 0;

	fail:
	nlmsg_free(msg);
	fail2:
	return nl_fail(error, error_function);
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
