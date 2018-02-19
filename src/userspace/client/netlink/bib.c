#include "bib.h"

#include "netlink.h"

struct foreach_args {
	bib_foreach_cb cb;
	void *args;
	struct request_bib_foreach request;
};

static int handle_foreach_response(struct jnl_response *response, void *args)
{
	struct bib_entry_usr *entries = response->payload;
	struct foreach_args *dargs = args;
	unsigned int entry_count;
	unsigned int e;
	int error;

	entry_count = response->payload_len / sizeof(*entries);
	for (e = 0; e < entry_count; e++) {
		error = dargs->cb(&entries[e], dargs->args);
		if (error)
			return error;
	}

	dargs->request.addr4_set = response->hdr->pending_data;
	if (entry_count > 0)
		dargs->request.addr4 = entries[entry_count - 1].addr4;

	return 0;
}

int bib_foreach(char *instance, l4_protocol proto,
		bib_foreach_cb cb, void *args)
{
	struct jnl_socket jsocket;
	struct foreach_args dargs;
	int error;

	dargs.cb = cb;
	dargs.args = args;
	dargs.request.l4_proto = proto;
	dargs.request.addr4_set = false;
	memset(&dargs.request.addr4, 0, sizeof(dargs.request.addr4));

	error = jnl_init_socket(&jsocket);
	if (error)
		return error;

	do {
		error = jnl_request(&jsocket, instance, MODE_BIB, OP_DISPLAY,
				&dargs.request, sizeof(dargs.request),
				handle_foreach_response, &dargs);
	} while (!error && dargs.request.addr4_set);

	jnl_destroy_socket(&jsocket);
	return error;
}

int bib_add(char *instance,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	struct request_bib_add request = {
		.l4_proto = proto,
		.addr6 = *a6,
		.addr4 = *a4,
	};
	return JNL_SIMPLE_REQUEST(instance, MODE_BIB, OP_ADD, request);
}

int bib_rm(char *instance,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	struct request_bib_rm request;
	memset(&request, 0, sizeof(request));

	request.l4_proto = proto;
	request.addr6_set = !!a6;
	if (a6)
		request.addr6 = *a6;
	request.addr4_set = !!a4;
	if (a4)
		request.addr4 = *a4;

	return JNL_SIMPLE_REQUEST(instance, MODE_BIB, OP_REMOVE, request);
}
