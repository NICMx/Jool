#include "usr/common/nl/blacklist4.h"

#include <errno.h>
#include "common/types.h"
#include "usr/common/netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_blacklist4)

struct foreach_args {
	blacklist4_foreach_cb cb;
	void *args;
	union request_blacklist4 *request;
};

static int blacklist4_display_response(struct jool_response *response, void *arg)
{
	struct ipv4_prefix *prefixes = response->payload;
	unsigned int prefix_count, i;
	struct foreach_args *args = arg;
	int error;

	prefix_count = response->payload_len / sizeof(*prefixes);

	for (i = 0; i < prefix_count; i++) {
		error = args->cb(&prefixes[i], args->args);
		if (error)
			return error;
	}

	args->request->display.offset_set = response->hdr->pending_data;
	if (prefix_count > 0)
		args->request->display.offset = prefixes[prefix_count - 1];

	return 0;
}

int blacklist4_foreach(char *iname, blacklist4_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	union request_blacklist4 *payload;
	struct foreach_args args;
	int error;

	hdr = (struct request_hdr *)request;
	payload = (union request_blacklist4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_BLACKLIST, OP_FOREACH, false);
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		error = netlink_request(iname, &request, sizeof(request),
				blacklist4_display_response, &args);
		if (error)
			return error;
	} while (args.request->display.offset_set);

	return 0;
}

/* TODO (NOW) remove this force? */
int blacklist4_add(char *iname, struct ipv4_prefix *addrs, bool force)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	union request_blacklist4 *payload;

	hdr = (struct request_hdr *)request;
	payload = (union request_blacklist4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_BLACKLIST, OP_ADD, force);
	payload->add.addrs = *addrs;

	return netlink_request(iname, request, sizeof(request), NULL, NULL);
}

int blacklist4_rm(char *iname, struct ipv4_prefix *addrs)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr;
	union request_blacklist4 *payload;

	hdr = (struct request_hdr *) request;
	payload = (union request_blacklist4 *) (request + HDR_LEN);

	init_request_hdr(hdr, MODE_BLACKLIST, OP_REMOVE, false);
	payload->rm.addrs = *addrs;

	return netlink_request(iname, request, sizeof(request), NULL, NULL);
}

int blacklist4_flush(char *iname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *) request;
	init_request_hdr(hdr, MODE_BLACKLIST, OP_FLUSH, false);
	return netlink_request(iname, request, sizeof(request), NULL, NULL);
}
