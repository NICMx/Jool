#include "usr/common/nl/pool4.h"

#include <errno.h>
#include "common/str_utils.h"
#include "common/types.h"
#include "usr/common/netlink.h"


#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


struct foreach_args {
	pool4_foreach_cb cb;
	void *args;
	union request_pool4 *request;
};

static int pool4_display_response(struct jool_response *response, void *arg)
{
	struct pool4_sample *samples = response->payload;
	unsigned int sample_count, i;
	struct foreach_args *args = arg;
	int error;

	sample_count = response->payload_len / sizeof(*samples);

	for (i = 0; i < sample_count; i++) {
		error = args->cb(&samples[i], args->args);
		if (error)
			return error;
	}

	args->request->display.offset_set = response->hdr->pending_data;
	if (sample_count > 0)
		args->request->display.offset = samples[sample_count - 1];

	return 0;
}

int pool4_foreach(char *instance, l4_protocol proto,
		pool4_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);
	struct foreach_args args;
	int error;

	init_request_hdr(hdr, MODE_POOL4, OP_FOREACH, false);
	payload->display.proto = proto;
	payload->display.offset_set = false;
	memset(&payload->display.offset, 0, sizeof(payload->display.offset));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		error = netlink_request(instance, &request, sizeof(request),
				pool4_display_response, &args);
		if (error)
			return error;
	} while (args.request->display.offset_set);

	return 0;
}

int pool4_add(char *iname, struct pool4_entry_usr *entry)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_ADD, false);
	payload->add = *entry;

	return netlink_request(iname, request, sizeof(request), NULL, NULL);
}

int pool4_rm(char *iname, struct pool4_entry_usr *entry, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_REMOVE, false);
	payload->rm.entry = *entry;
	payload->rm.quick = quick;

	return netlink_request(iname, request, sizeof(request), NULL, NULL);
}

int pool4_flush(char *iname, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_FLUSH, false);
	payload->flush.quick = quick;

	return netlink_request(iname, &request, sizeof(request), NULL, NULL);
}
