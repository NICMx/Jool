#include "usr/common/nl/session.h"

#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include "common/config.h"
#include "common/session.h"
#include "usr/common/str_utils.h"
#include "common/types.h"
#include "usr/common/netlink.h"
#include "usr/common/dns.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_session)

struct foreach_args {
	session_foreach_cb cb;
	void *args;
	struct request_session *request;
};

static int session_display_response(struct jool_response *response, void *arg)
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

	args->request->display.offset_set = response->hdr->pending_data;
	if (entry_count > 0) {
		struct session_entry_usr *last = &entries[entry_count - 1];
		args->request->display.offset.src = last->src4;
		args->request->display.offset.dst = last->dst4;
	}

	return 0;
}

int session_foreach(char *iname, l4_protocol proto,
		session_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	struct request_session *payload;
	struct foreach_args args;
	bool error;

	hdr = (struct request_hdr *)request;
	payload = (struct request_session *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_SESSION, OP_FOREACH, false);
	payload->l4_proto = proto;
	payload->display.offset_set = false;
	memset(&payload->display.offset.src, 0,
			sizeof(payload->display.offset.src));
	memset(&payload->display.offset.dst, 0,
			sizeof(payload->display.offset.dst));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		error = netlink_request(iname, request, sizeof(request),
				session_display_response, &args);
	} while (!error && args.request->display.offset_set);

	return error;
}

