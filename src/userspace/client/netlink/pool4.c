#include "pool4.h"

#include "netlink.h"

struct foreach_args {
	pool4_foreach_cb cb;
	void *args;
	struct request_pool4_foreach request;
};

static int handle_foreach_response(struct jnl_response *response, void *arg)
{
	struct pool4_sample *samples = response->payload;
	struct foreach_args *args = arg;
	unsigned int sample_count, i;
	int error;

	sample_count = response->payload_len / sizeof(*samples);
	for (i = 0; i < sample_count; i++) {
		error = args->cb(&samples[i], args->args);
		if (error)
			return error;
	}

	args->request.offset_set = response->hdr->pending_data;
	if (sample_count > 0)
		args->request.offset = samples[sample_count - 1];
	return 0;
}

int pool4_foreach(l4_protocol proto, pool4_foreach_cb cb, void *args)
{
	struct jnl_socket jsocket;
	struct foreach_args fargs;
	int error;

	fargs.cb = cb;
	fargs.args = args;
	fargs.request.proto = proto;
	fargs.request.offset_set = false;
	memset(&fargs.request.offset, 0, sizeof(fargs.request.offset));

	error = jnl_init_socket(&jsocket);
	if (error)
		return error;

	do {
		error = jnl_request(&jsocket, MODE_POOL4, OP_DISPLAY,
				&fargs.request, sizeof(fargs.request),
				handle_foreach_response, &fargs);
	} while (!error && fargs.request.offset_set);

	jnl_destroy_socket(&jsocket);
	return error;
}

int pool4_add(struct pool4_entry_usr *entry, bool force)
{
	struct request_pool4_add request;
	request.entry = *entry;
	return JNL_SIMPLE_REQUEST(MODE_POOL4, OP_ADD, request);
}

//int pool4_update(struct pool4_update *args)
//{
//	struct request_pool4_update payload;
//
//	init_request_hdr(hdr, MODE_POOL4, OP_UPDATE);
//	payload->update = *args;
//
//	return netlink_request(request, sizeof(request), NULL, NULL);
//}

int pool4_rm(struct pool4_entry_usr *entry, bool quick)
{
	struct request_pool4_rm request = {
			.entry = *entry,
			.quick = quick,
	};
	return JNL_SIMPLE_REQUEST(MODE_POOL4, OP_REMOVE, request);
}

int pool4_flush(bool quick)
{
	struct request_pool4_flush request = { .quick = quick, };
	return JNL_SIMPLE_REQUEST(MODE_POOL4, OP_FLUSH, request);
}
