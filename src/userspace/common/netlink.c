#include "netlink.h"

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <errno.h>
#include "nl-protocol.h"

struct response_cb {
	jnl_response_cb cb;
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

/*
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nlerr,
		void *arg)
{
	log_err("Error: %s", ((char *)nlerr) + sizeof(*nlerr));
	log_err("(Error code: %d)", nlerr->error);
	error_handler_called = true;
	return -abs(nlerr->error);
}
*/

static int print_error_msg(struct jnl_response *response)
{
	char *msg;

	error_handler_called = true;

	if (response->payload_len <= 0) {
		log_err("Error (The kernel's response is empty so the cause is unknown.)");
		goto end;
	}

	msg = response->payload;
	if (msg[response->payload_len - 1] != '\0') {
		log_err("Error (The kernel's response is not a string so the cause is unknown.)");
		goto end;
	}

	log_err("Jool Error: %s", msg);
	/* Fall through. */

end:
	log_err("(Error code: %u)", response->hdr->error_code);
	return response->hdr->error_code;
}

int netlink_parse_response(void *data, size_t data_len, struct jnl_response *result)
{
	if (data_len < sizeof(struct response_hdr)) {
		log_err("The module's response is too small to contain a response header.");
		return -EINVAL;
	}

	result->hdr = data;
	result->payload = result->hdr + 1;
	result->payload_len = data_len - sizeof(struct response_hdr);

	return result->hdr->error_code ? print_error_msg(result) : 0;
}

/*
 * Heads up:
 * Netlink wants this function to return either a negative error code or an enum
 * nl_cb_action.
 * Because NL_SKIP == EPERM and NL_STOP == ENOENT, you should mind the sign of
 * the result HARD.
 */
static int response_handler(struct nl_msg *msg, void *void_arg)
{
	struct jnl_response response;
	struct nlattr *attrs[__ATTR_MAX + 1];
	struct response_cb *arg;
	int error;

	error = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, __ATTR_MAX, NULL);
	if (error) {
		log_err("%s (error code %d)", nl_geterror(error), error);
		return -abs(error);
	}

	if (!attrs[ATTR_DATA]) {
		log_err("The module's response seems to be empty.");
		return -EINVAL;
	}
	error = netlink_parse_response(nla_data(attrs[ATTR_DATA]),
			nla_len(attrs[ATTR_DATA]),
			&response);
	if (error)
		return -abs(error);

	arg = void_arg;
	return (arg && arg->cb) ? (-abs(arg->cb(&response, arg->arg))) : 0;
}

static int build_request(struct jnl_socket *socket, char *instance,
		enum config_mode mode, enum config_operation op,
		void *data, int data_len,
		struct nl_msg **result)
{
	struct request_hdr *hdr;
	struct nl_msg *msg;
	int error;

	msg = nlmsg_alloc();
	if (!msg) {
		log_err("Out of memory.");
		return -ENOMEM;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, socket->family,
			sizeof(struct request_hdr), 0, JOOL_COMMAND, 1);
	if (!hdr) {
		log_err("Unknown error building the packet to the kernel.");
		nlmsg_free(msg);
		return -EINVAL;
	}
	init_request_hdr(hdr, mode, op);

	if (instance) {
		error = nla_put_string(msg, ATTR_INSTANCE_NAME, instance);
		if (error) {
			log_err("Could not write the instance name attribute on the packet.");
			nlmsg_free(msg);
			netlink_print_error(error);
			return error;
		}
	}

	error = nla_put(msg, ATTR_DATA, data_len, data);
	if (error) {
		log_err("Could not write the payload of the packet.");
		nlmsg_free(msg);
		netlink_print_error(error);
		return error;
	}

	*result = msg;
	return 0;
}

int jnl_request(struct jnl_socket *socket, char *instance,
		enum config_mode mode, enum config_operation op,
		void *data, int data_len,
		jnl_response_cb cb, void *cb_arg)
{
	struct nl_msg *msg;
	struct response_cb callback = { .cb = cb, .arg = cb_arg };
	int error;

	if (cb) {
		error = nl_socket_modify_cb(socket->sk,
				NL_CB_MSG_IN, NL_CB_CUSTOM,
				response_handler, &callback);
		if (error < 0) {
			log_err("Could not register response handler.");
			log_err("I will not be able to parse Jool's response, so I won't send the request.");
			return netlink_print_error(error);
		}
	}

	error = build_request(socket, instance, mode, op, data, data_len, &msg);
	if (error)
		return error;
	error = nl_send_auto(socket->sk, msg);
	nlmsg_free(msg);
	if (error < 0) {
		log_err("Could not dispatch the request to kernelspace.");
		return netlink_print_error(error);
	}

	if (cb) {
		error = nl_recvmsgs_default(socket->sk);
		if (error < 0) {
			if (error_handler_called) {
				error_handler_called = false;
				return error;
			}
			log_err("Error receiving the kernel module's response.");
			return netlink_print_error(error);
		}
	}

	return 0;
}

int jnl_single_request(char *instance,
		enum config_mode mode, enum config_operation op,
		void *data, int data_len,
		jnl_response_cb cb, void *cb_arg)
{
	struct jnl_socket socket;
	int error;

	error = jnl_init_socket(&socket);
	if (error)
		return error;

	error = jnl_request(&socket, instance, mode, op, data, data_len,
			cb, cb_arg);

	jnl_destroy_socket(&socket);
	return error;
}
