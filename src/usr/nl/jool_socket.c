#include "jool_socket.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "common/config.h"


/*
 * Assert we're compiling with libnl version >= 3.0
 *
 * Note: it looks like this shouldn't be here, since it's the configure script's
 * responsibility.
 * However, the configure script seems to fail to detect this properly on RedHat
 * (and maybe others).
 */
#if !defined(LIBNL_VER_NUM)
	#error "Missing LIBNL dependency (need at least version 3)."
#endif
#if LIBNL_VER_NUM < LIBNL_VER(3, 0)
	#error "Unsupported LIBNL library version number (< 3.0)."
#endif


struct response_cb {
	jool_response_cb cb;
	void *arg;
	struct jool_result result;
};

static struct jool_result print_error_msg(struct jool_response *response)
{
	int error_code;
	char *msg;

	error_code = response->hdr->error_code;

	if (response->payload_len <= 0) {
		msg = strerror(error_code);
	} else {
		msg = response->payload;
		if (msg[response->payload_len - 1] != '\0')
			msg = strerror(error_code);
	}

	return result_from_error(
		error_code,
		"The kernel module returned error %d: %s", error_code, msg
	);
}

struct jool_result netlink_parse_response(void *data, size_t data_len,
		struct jool_response *response)
{
	if (data_len < sizeof(struct response_hdr)) {
		return result_from_error(
			-EINVAL,
			"The response of the module is too small. (%zu bytes)",
			data_len
		);
	}

	response->hdr = data;
	response->payload = response->hdr + 1;
	response->payload_len = data_len - sizeof(struct response_hdr);

	return response->hdr->error_code
			? print_error_msg(response)
			: result_success();
}

/*
 * Heads up:
 * Netlink wants this function to return either a negative error code or an enum
 * nl_cb_action.
 * Because NL_SKIP == EPERM and NL_STOP == ENOENT, you really need to mind the
 * sign of the result.
 */
static int response_handler(struct nl_msg *msg, void *void_arg)
{
	struct jool_response response;
	struct nlattr *attrs[__ATTR_MAX + 1];
	struct response_cb *arg = void_arg;
	int error;

	/* Also: arg->result needs to be set on all paths. */

	error = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, __ATTR_MAX, NULL);
	if (error) {
		arg->result = result_from_error(
			error,
			"%s", nl_geterror(error)
		);
		goto return_error;
	}

	if (!attrs[ATTR_DATA]) {
		arg->result = result_from_error(
			-EINVAL,
			"The module's response seems to be empty."
		);
		return -EINVAL;
	}
	arg->result = netlink_parse_response(
		nla_data(attrs[ATTR_DATA]),
		nla_len(attrs[ATTR_DATA]),
		&response
	);
	if (arg->result.error)
		goto return_result;

	if (arg->cb) {
		arg->result = arg->cb(&response, arg->arg);
		if (arg->result.error)
			goto return_result;
	}

	return 0;

return_result:
	error = arg->result.error;
return_error:
	return (error < 0) ? error : -error;
}

struct jool_result netlink_send(struct jool_socket *socket, char *iname,
		void *request, __u32 request_len)
{
	struct nl_msg *msg;
	int error;

	msg = nlmsg_alloc();
	if (!msg) {
		return result_from_error(
			-EINVAL,
			"Request allocation failure (Unknown cause)"
		);
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, socket->genl_family,
			0, 0, JOOL_COMMAND, 1)) {
		nlmsg_free(msg);
		return result_from_error(
			-EINVAL,
			"Unknown error building the packet to the kernel."
		);
	}

	/*
	 * The kernel module already knows that the default instance name is
	 * INAME_DEFAULT.
	 */
	if (iname && strcmp(iname, INAME_DEFAULT) != 0) {
		error = nla_put_string(msg, ATTR_INAME, iname);
		if (error) {
			nlmsg_free(msg);
			return result_from_error(
				error,
				"(Instance) write attempt on packet failed: %s",
				nl_geterror(error)
			);
		}
	}

	error = nla_put(msg, ATTR_DATA, request_len, request);
	if (error) {
		nlmsg_free(msg);
		return result_from_error(
			error,
			"(Data) write attempt on packet failed: %s",
			nl_geterror(error)
		);
	}

	error = nl_send_auto(socket->sk, msg);
	nlmsg_free(msg);
	if (error < 0) {
		return result_from_error(
			error,
			"Could not dispatch the request to kernelspace: %s",
			nl_geterror(error)
		);
	}

	return result_success();
}

/**
 * @iname can be NULL. The kernel module will assume that the instance name is
 * "" (empty string).
 */
struct jool_result netlink_request(struct jool_socket *sk, char *iname,
		void *request, __u32 request_len,
		jool_response_cb cb, void *cb_arg)
{

	struct response_cb callback;
	struct jool_result result;

	callback.cb = cb;
	callback.arg = cb_arg;
	/* Clear out JRF_INITIALIZED and error code */
	memset(&callback.result, 0, sizeof(callback.result));

	result.error = nl_socket_modify_cb(sk->sk, NL_CB_MSG_IN, NL_CB_CUSTOM,
			response_handler, &callback);
	if (result.error < 0) {
		return result_from_error(
			result.error,
			"Could not register response handler: %s\n",
			nl_geterror(result.error)
		);
	}

	result = netlink_send(sk, iname, request, request_len);
	if (result.error)
		return result;

	result.error = nl_recvmsgs_default(sk->sk);
	if (result.error < 0) {
		if ((callback.result.flags & JRF_INITIALIZED)
				&& callback.result.error) {
			/* nl_recvmsgs_default() failed during our callback */
			return callback.result;
		}

		/* nl_recvmsgs_default() failed before or after our callback */
		return result_from_error(
			result.error,
			"Error receiving the kernel module's response: %s",
			nl_geterror(result.error)
		);
	}

	return result_success();
}

/**
 * Contract: The result will contain 0 on success, -ESRCH on module likely not
 * modprobed, else -EINVAL.
 */
struct jool_result netlink_setup(struct jool_socket *socket, xlator_type xt)
{
	char const *family;
	int error;

	switch (xt) {
	case XT_SIIT:
		family = GNL_SIIT_JOOL_FAMILY;
		break;
	case XT_NAT64:
		family = GNL_NAT64_JOOL_FAMILY;
		break;
	default:
		return result_from_error(
			-EINVAL,
			"Unknown translator type"
		);
	}

	socket->sk = nl_socket_alloc();
	if (!socket->sk) {
		return result_from_error(
			-EINVAL,
			"Netlink socket allocation failure (Unknown cause)"
		);
	}

	/*
	 * For normal requests, we handle ACKs ourselves. The reason is that
	 * Netlink ACK errors do not contain the friendly error string, so
	 * they're useless to us.
	 * https://github.com/NICMx/Jool/issues/169
	 *
	 * In joold's case, it's because ACKs would only slow us down.
	 * We use UDP in the network, so we're assuming best-effort anyway.
	 */
	nl_socket_disable_auto_ack(socket->sk);

	error = genl_connect(socket->sk);
	if (error) {
		nl_socket_free(socket->sk);
		return result_from_error(
			-EINVAL,
			"Could not open the socket to kernelspace: %s",
			nl_geterror(error)
		);
	}

	socket->xt = xt;
	socket->genl_family = genl_ctrl_resolve(socket->sk, family);
	if (socket->genl_family < 0) {
		nl_socket_free(socket->sk);
		return result_from_error(
			-ESRCH,
			"Jool's socket family doesn't seem to exist.\n"
			"(This probably means Jool hasn't been modprobed.)\n"
			"Netlink error message: %s",
			nl_geterror(socket->genl_family)
		);
	}

	return result_success();
}

void netlink_teardown(struct jool_socket *socket)
{
	nl_close(socket->sk);
	nl_socket_free(socket->sk);
}
