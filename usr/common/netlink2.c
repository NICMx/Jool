#include "nat64/usr/netlink.h"

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <errno.h>
#include "nat64/common/config.h"
#include "nat64/common/types.h"

struct response_cb {
	jool_response_cb cb;
	void *arg;
};

static struct nl_sock *sk;
static int family;

/*
 * This will need to be refactored if some day we need multiple request calls
 * in separate threads.
 * At this point this is the best I can do because there's no other way to tell
 * whether the error returned by nl_recvmsgs_default() is a Netlink error or a
 * Jool error.
 */
bool error_handler_called = false;

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

static int print_error_msg(struct jool_response *response)
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

int netlink_parse_response(void *data, size_t data_len, struct jool_response *result)
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
	struct jool_response response;
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

int netlink_request(void *request, __u32 request_len,
		jool_response_cb cb, void *cb_arg)
{
	struct nl_msg *msg;
	struct response_cb callback = { .cb = cb, .arg = cb_arg };
	int error;

	error = nl_socket_modify_cb(sk, NL_CB_MSG_IN, NL_CB_CUSTOM,
			response_handler, &callback);
	if (error < 0) {
		log_err("Could not register response handler.");
		log_err("I will not be able to parse Jool's response, so I won't send the request.");
		return netlink_print_error(error);
	}

	msg = nlmsg_alloc();
	if (!msg) {
		log_err("Could not allocate the message to the kernel; it seems we're out of memory.");
		return -ENOMEM;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
			JOOL_COMMAND, 1)) {
		log_err("Unknown error building the packet to the kernel.");
		nlmsg_free(msg);
		return -EINVAL;
	}

	error = nla_put(msg, ATTR_DATA, request_len, request);
	if (error) {
		log_err("Could not write on the packet to kernelspace.");
		nlmsg_free(msg);
		return netlink_print_error(error);
	}

	error = nl_send_auto(sk, msg);
	nlmsg_free(msg);
	if (error < 0) {
		log_err("Could not dispatch the request to kernelspace.");
		return netlink_print_error(error);
	}

	error = nl_recvmsgs_default(sk);
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

int netlink_request_simple(void *request, __u32 request_len)
{
	struct nl_msg *msg;
	int error;

	msg = nlmsg_alloc();
	if (!msg) {
		log_err("Could not allocate the request; it seems we're out of memory.");
		return -ENOMEM;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
			JOOL_COMMAND, 1)) {
		log_err("Unknown error building the packet to the kernel.");
		nlmsg_free(msg);
		return -EINVAL;
	}

	error = nla_put(msg, ATTR_DATA, request_len, request);
	if (error) {
		log_err("Could not write on the packet to kernelspace.");
		nlmsg_free(msg);
		return netlink_print_error(error);
	}

	error = nl_send_auto(sk, msg);
	nlmsg_free(msg);
	if (error < 0) {
		log_err("Could not dispatch the request to kernelspace.");
		return netlink_print_error(error);
	}

	return 0;
}

int netlink_init(void)
{
	int error;

	sk = nl_socket_alloc();
	if (!sk) {
		log_err("Could not allocate the socket to kernelspace; it seems we're out of memory.");
		return -ENOMEM;
	}

	/*
	 * We handle ACKs ourselves. The reason is that Netlink ACK errors do
	 * not contain the friendly error string, so they're useless to us.
	 * https://github.com/NICMx/Jool/issues/169
	 */
	nl_socket_disable_auto_ack(sk);

	error = genl_connect(sk);
	if (error) {
		log_err("Could not open the socket to kernelspace.");
		goto fail;
	}

	family = genl_ctrl_resolve(sk, GNL_JOOL_FAMILY_NAME);
	if (family < 0) {
		log_err("Jool's socket family doesn't seem to exist.");
		log_err("(This probably means Jool hasn't been modprobed.)");
		error = family;
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
	nl_socket_free(sk);
	return netlink_print_error(error);
}

void netlink_destroy(void)
{
	nl_close(sk);
	nl_socket_free(sk);
}
