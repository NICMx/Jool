#include "netlink.h"

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <errno.h>
#include "nl-protocol.h"

struct response_cb {
	nl_recvmsg_msg_cb_t cb;
	void *arg;
};

/*
 * This will need to be refactored if some day we need multiple request calls
 * in separate threads.
 * At this point this is the best I can do because there's no other way to tell
 * whether the error returned by nl_recvmsgs_default() is a Netlink error or a
 * Jool error.
 */
bool error_handler_called = false;

int jnl_init_socket(struct jnl_socket *socket)
{
	int error;

	socket->sk = nl_socket_alloc();
	if (!socket->sk) {
		log_err("Could not allocate the socket to kernelspace; it seems we're out of memory.");
		return -ENOMEM;
	}

	/*
	 * We handle ACKs ourselves. The reason is that Netlink ACK errors do
	 * not contain the friendly error string, so they're useless to us.
	 * https://github.com/NICMx/Jool/issues/169
	 */
	nl_socket_disable_auto_ack(socket->sk);

	error = genl_connect(socket->sk);
	if (error) {
		log_err("Could not open the socket to kernelspace.");
		goto fail;
	}

	socket->family = genl_ctrl_resolve(socket->sk, GNL_JOOL_FAMILY_NAME);
	if (socket->family < 0) {
		log_err("Jool's socket family doesn't seem to exist.");
		log_err("(This probably means Jool hasn't been modprobed.)");
		error = socket->family;
		goto fail;
	}

	/*
	error = nl_socket_modify_err_cb(sk, NL_CB_CUSTOM, error_handler, NULL);
	if (error) {
		log_err("Could not register the error handler function.");
		log_err("This means the socket to kernelspace cannot be used.");
		goto fail;
	}
	*/

	return 0;

fail:
	nl_socket_free(socket->sk);
	return netlink_print_error(error);
}

void jnl_destroy_socket(struct jnl_socket *socket)
{
	nl_close(socket->sk);
	nl_socket_free(socket->sk);
}

int netlink_print_error(int error)
{
	log_err("Netlink error message: '%s' (Code %d)",
			nl_geterror(error), error);
	return error;
}

static int handle_jool_error(struct nl_msg *msg)
{
	struct genlmsghdr *ghdr;
	struct jnlmsghdr *jhdr;
	struct nlattr *attr;

	error_handler_called = true;

	ghdr = genlmsg_hdr(nlmsg_hdr(msg));
	jhdr = genlmsg_user_hdr(ghdr);

	attr = genlmsg_attrdata(ghdr, JNL_HDR_LEN);
	if (!nla_ok(attr, genlmsg_attrlen(ghdr, JNL_HDR_LEN)))
		goto no_msg;

	if (attr->nla_type != JNLA_ERROR_MSG)
		goto no_msg;
	/* TODO check that the last character is NULL? */

	log_err("Error: %s", nla_get_string(attr));
	return -jhdr->error;

no_msg:
	log_err("Error. The kernel's response is empty so the cause is unknown.");
	log_err("Try the kernel ring buffer. (Usually just run `dmesg | tail`.)");
	log_err("This is probably a bug. Please report it at https://github.com/NICMx/Jool/issues.");
	return -jhdr->error;
}

/*
 * Heads up:
 * Netlink wants this function to return either a negative error code or an enum
 * nl_cb_action.
 * Because NL_SKIP == EPERM and NL_STOP == ENOENT, do mind the sign of the
 * result and don't make assumptions.
 */
static int response_handler(struct nl_msg *msg, void *void_arg)
{
	struct jnlmsghdr *jhdr;
	struct response_cb *arg;

	jhdr = genlmsg_user_hdr(genlmsg_hdr(nlmsg_hdr(msg)));
	if (jhdr->error)
		return handle_jool_error(msg);

	arg = void_arg;
	if (!arg->cb)
		return 0;

	return -abs(arg->cb(msg, arg->arg));
}

int jnl_create_request(char *instance, jool_genl_cmd cmd, struct nl_msg **result)
{
	struct nl_msg *msg;
	int error;

	msg = nlmsg_alloc();
	if (!msg) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	/* Family will be patched later at jnl_request(). */
	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, 0, JNL_HDR_LEN, 0,
			cmd, JOOL_VERSION_MAJOR)) {
		log_err("Unknown error building the packet to the kernel.");
		nlmsg_free(msg);
		return -EINVAL;
	}

	error = nla_put_string(msg, JNLA_INSTANCE_NAME, instance);
	if (error) {
		log_err("Could not write the instance name attribute on the packet.");
		nlmsg_free(msg);
		netlink_print_error(error);
		return error;
	}

	*result = msg;
	return 0;
}

/**
 * Swallows @request.
 */
int jnl_request(struct jnl_socket *socket, struct nl_msg *request,
		nl_recvmsg_msg_cb_t cb, void *cb_arg)
{
	struct response_cb rcb = { .cb = cb, .arg = cb_arg };
	int error;

	error = nl_socket_modify_cb(socket->sk, NL_CB_MSG_IN, NL_CB_CUSTOM,
			response_handler, &rcb);
	if (error < 0) {
		log_err("Could not register response handler.");
		log_err("I will not be able to parse Jool's response, so I won't send the request.");
		nlmsg_free(request);
		return netlink_print_error(error);
	}

	/* Patch family. */
	nlmsg_hdr(request)->nlmsg_type = socket->family;

	error = nl_send_auto(socket->sk, request);
	nlmsg_free(request);
	if (error < 0) {
		log_err("Could not dispatch the request to kernelspace.");
		return netlink_print_error(error);
	}

	error = nl_recvmsgs_default(socket->sk);
	if (error < 0) {
		if (error_handler_called) {
			error_handler_called = false;
			return error;
		}
		log_err("Error receiving the kernel module's response.");
		return netlink_print_error(error);
	}

	return 0;
}

/**
 * Swallows @request.
 */
int jnl_single_request(struct nl_msg *request)
{
	struct jnl_socket socket;
	int error;

	error = jnl_init_socket(&socket);
	if (error) {
		nlmsg_free(request);
		return error;
	}

	error = jnl_request(&socket, request, NULL, NULL);

	jnl_destroy_socket(&socket);
	return error;
}
