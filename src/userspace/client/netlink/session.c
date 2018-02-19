#include "session.h"

#include "netlink.h"
#include "userspace-types.h"

struct foreach_args {
	session_foreach_cb cb;
	void *args;

	unsigned int row_count;
	struct request_session_display request;
};

static int handle_foreach_response(struct jnl_response *response, void *arg)
{
	struct session_entry_usr *entries = response->payload;
	struct foreach_args *args = arg;
	__u16 entry_count, i;
	int error;

	entry_count = response->payload_len / sizeof(*entries);
	for (i = 0; i < entry_count; i++) {
		error = args->cb(&entries[i], args->args);
		if (error)
			return error;
	}

	args->row_count += entry_count;
	args->request.offset_set = response->hdr->pending_data;
	if (entry_count > 0) {
		struct session_entry_usr *last = &entries[entry_count - 1];
		args->request.offset.src = last->src4;
		args->request.offset.dst = last->dst4;
	}

	return 0;
}

int session_foreach(char *instance, l4_protocol proto, session_foreach_cb cb,
		void *args)
{
	struct jnl_socket jsocket;
	struct foreach_args dargs;
	bool error;

	dargs.cb = cb;
	dargs.args = args;
	dargs.row_count = 0;
	dargs.request.l4_proto = proto;
	dargs.request.offset_set = false;
	memset(&dargs.request.offset.src, 0, sizeof(dargs.request.offset.src));
	memset(&dargs.request.offset.dst, 0, sizeof(dargs.request.offset.dst));

	error = jnl_init_socket(&jsocket);
	if (error)
		return error;

	do {
		error = jnl_request(&jsocket, instance, MODE_SESSION, OP_DISPLAY,
				&dargs.request, sizeof(dargs.request),
				handle_foreach_response, &dargs);
	} while (!error && dargs.request.offset_set);

	jnl_destroy_socket(&jsocket);
	return error;
}
