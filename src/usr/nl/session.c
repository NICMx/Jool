#include "session.h"

#include "jool_socket.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_session)

struct foreach_args {
	session_foreach_cb cb;
	void *args;
	struct request_session *request;
};

static struct jool_result session_foreach_response(
		struct jool_response *response, void *arg)
{
	struct session_entry_usr *entries = response->payload;
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
	if (entry_count > 0) {
		struct session_entry_usr *last = &entries[entry_count - 1];
		args->request->foreach.offset.src = last->src4;
		args->request->foreach.offset.dst = last->dst4;
	}

	return result_success();
}

struct jool_result session_foreach(struct jool_socket *sk, char *iname,
		l4_protocol proto, session_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	struct request_session *payload;
	struct foreach_args args;
	struct jool_result result;

	hdr = (struct request_hdr *)request;
	payload = (struct request_session *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_SESSION, OP_FOREACH, false);
	payload->l4_proto = proto;
	payload->foreach.offset_set = false;
	memset(&payload->foreach.offset.src, 0,
			sizeof(payload->foreach.offset.src));
	memset(&payload->foreach.offset.dst, 0,
			sizeof(payload->foreach.offset.dst));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		result = netlink_request(sk, iname, request, sizeof(request),
				session_foreach_response, &args);
	} while (!result.error && args.request->foreach.offset_set);

	return result;
}
