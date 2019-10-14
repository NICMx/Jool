#include "instance.h"

#include <errno.h>

#include "jool_socket.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_instance)

struct foreach_args {
	instance_foreach_entry cb;
	void *args;
	union request_instance *request;
};

static struct jool_result instance_foreach_response(
		struct jool_response *response, void *arg)
{
	struct instance_entry_usr *entries = response->payload;
	struct foreach_args *args = arg;
	__u16 entry_count, i;
	struct jool_result result;

	entry_count = response->payload_len / sizeof(*entries);

	for (i = 0; i < entry_count; i++) {
		result = args->cb(&entries[i], args->args);
		if (result.error)
			return result;
	}

	args->request->foreach.offset_set = response->hdr->pending_data;
	if (entry_count > 0)
		args->request->foreach.offset = entries[entry_count - 1];

	return result_success();
}

struct jool_result instance_foreach(struct jool_socket *sk,
		instance_foreach_entry cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	union request_instance *payload;
	struct foreach_args args;
	struct jool_result result;

	hdr = (struct request_hdr *)request;
	payload = (union request_instance *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_INSTANCE, OP_FOREACH, false);
	payload->foreach.offset_set = false;
	memset(&payload->foreach.offset, 0, sizeof(payload->foreach.offset));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		result = netlink_request(sk, NULL, request, sizeof(request),
				instance_foreach_response, &args);
		if (result.error)
			return result;
	} while (payload->foreach.offset_set);

	return result_success();
}

static struct jool_result jool_hello_cb(struct jool_response *response,
		void *status)
{
	struct instance_hello_response *payload;

	if (response->payload_len != sizeof(struct instance_hello_response)) {
		return result_from_error(
			-EINVAL,
			"Jool's response has a bogus length. (expected %zu, got %zu).",
			sizeof(struct instance_hello_response),
			response->payload_len
		);
	}

	payload = response->payload;
	*((enum instance_hello_status *) status) = payload->status;
	return result_success();
}

/**
 * If the instance exists, @result will be zero. If the instance does not exist,
 * @result will be 1.
 */
struct jool_result instance_hello(struct jool_socket *sk, char *iname,
		enum instance_hello_status *status)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	union request_instance *payload;
	int error;

	error = iname_validate(iname, true);
	if (error) {
		return result_from_error(
			error,
			INAME_VALIDATE_ERRMSG,
			INAME_MAX_LEN - 1
		);
	}

	hdr = (struct request_hdr *)request;
	payload = (union request_instance *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_INSTANCE, OP_TEST, false);
	strcpy(payload->hello.iname, iname ? iname : INAME_DEFAULT);

	return netlink_request(sk, NULL, &request, sizeof(request),
			jool_hello_cb, status);
}

struct jool_result instance_add(struct jool_socket *sk, xlator_framework xf,
		char *iname, struct ipv6_prefix *pool6)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	union request_instance *payload;
	int error;

	error = xf_validate(xf);
	if (error)
		return result_from_error(error, XF_VALIDATE_ERRMSG);

	error = iname_validate(iname, true);
	if (error) {
		return result_from_error(
			error,
			INAME_VALIDATE_ERRMSG,
			INAME_MAX_LEN - 1
		);
	}

	hdr = (struct request_hdr *)request;
	payload = (union request_instance *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_INSTANCE, OP_ADD, false);
	payload->add.xf = xf;
	strcpy(payload->add.iname, iname ? iname : INAME_DEFAULT);
	if (pool6) {
		payload->add.pool6.set = true;
		payload->add.pool6.prefix = *pool6;
	} else {
		payload->add.pool6.set = false;
		memset(&payload->add.pool6.prefix, 0,
				sizeof(payload->add.pool6.prefix));
	}

	return netlink_request(sk, NULL, request, sizeof(request), NULL, NULL);
}

struct jool_result instance_rm(struct jool_socket *sk, char *iname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_instance *payload = (union request_instance *)
			(request + HDR_LEN);
	int error;

	error = iname_validate(iname, true);
	if (error) {
		return result_from_error(
			error,
			INAME_VALIDATE_ERRMSG,
			INAME_MAX_LEN - 1
		);
	}

	init_request_hdr(hdr, sk->xt, MODE_INSTANCE, OP_REMOVE, false);
	strcpy(payload->rm.iname, iname ? iname : INAME_DEFAULT);

	return netlink_request(sk, NULL, request, sizeof(request), NULL, NULL);
}

struct jool_result instance_flush(struct jool_socket *sk)
{
	struct request_hdr request;
	init_request_hdr(&request, sk->xt, MODE_INSTANCE, OP_FLUSH, false);
	return netlink_request(sk, NULL, &request, sizeof(request), NULL, NULL);
}
