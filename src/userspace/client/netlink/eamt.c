#include "eamt.h"

#include "netlink.h"

struct foreach_args {
	eamt_foreach_cb cb;
	void *args;
	struct request_eamt_display request;
};

static int handle_foreach_response(struct jnl_response *response, void *args)
{
	struct eamt_entry *entries = response->payload;
	struct foreach_args *eargs = args;
	unsigned int entry_count;
	unsigned int e;
	int error;

	entry_count = response->payload_len / sizeof(*entries);
	for (e = 0; e < entry_count; e++) {
		error = eargs->cb(&entries[e], eargs->args);
		if (error)
			return error;
	}

	eargs->request.prefix4_set = response->hdr->pending_data;
	if (entry_count > 0) {
		struct eamt_entry *last = &entries[entry_count - 1];
		eargs->request.prefix4 = last->prefix4;
	}
	return 0;
}

int eamt_foreach(eamt_foreach_cb cb, void *args)
{
	struct jnl_socket jsocket;
	struct foreach_args eargs;
	int error;

	eargs.cb = cb;
	eargs.args = args;
	eargs.request.prefix4_set = false;
	memset(&eargs.request.prefix4, 0, sizeof(eargs.request.prefix4));

	error = jnl_init_socket(&jsocket);
	if (error)
		return error;

	do {
		error = jnl_request(&jsocket, MODE_EAMT, OP_DISPLAY,
				&eargs.request, sizeof(eargs.request),
				handle_foreach_response, &eargs);
	} while (!error && eargs.request.prefix4_set);

	jnl_destroy_socket(&jsocket);
	return error;
}

int eamt_add(struct ipv6_prefix *p6, struct ipv4_prefix *p4, bool force)
{
	struct request_eamt_add request;

	if (!p6 || !p4) {
		log_err("Both prefixes are mandatory arguments for EAMT add.");
		return -EINVAL;
	}

	request.prefix6 = *p6;
	request.prefix4 = *p4;
	request.force = force;

	return JNL_SIMPLE_REQUEST(MODE_EAMT, OP_ADD, request);
}

int eamt_rm(struct ipv6_prefix *p6, struct ipv4_prefix *p4)
{
	struct request_eamt_rm request;
	memset(&request, 0, sizeof(request));

	request.prefix6_set = !!p6;
	if (p6)
		request.prefix6 = *p6;
	request.prefix4_set = !!p4;
	if (p4)
		request.prefix4 = *p4;

	return JNL_SIMPLE_REQUEST(MODE_EAMT, OP_REMOVE, request);
}

int eamt_flush(void)
{
	return JNL_HDR_REQUEST(MODE_EAMT, OP_FLUSH);
}
