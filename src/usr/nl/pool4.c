#include "pool4.h"

#include <errno.h>

#include "jool_socket.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_pool4)


struct foreach_args {
	pool4_foreach_cb cb;
	void *args;
	union request_pool4 *request;
};

static struct jool_result pool4_foreach_response(struct jool_response *response,
		void *arg)
{
	struct pool4_sample *samples = response->payload;
	unsigned int sample_count, i;
	struct foreach_args *args = arg;
	struct jool_result result;

	sample_count = response->payload_len / sizeof(*samples);

	for (i = 0; i < sample_count; i++) {
		result = args->cb(&samples[i], args->args);
		if (result.error)
			return result;
	}

	args->request->foreach.offset_set = response->hdr->pending_data;
	if (sample_count > 0)
		args->request->foreach.offset = samples[sample_count - 1];

	return result_success();
}

struct jool_result pool4_foreach(struct jool_socket *sk, char *iname,
		l4_protocol proto, pool4_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);
	struct foreach_args args;
	struct jool_result result;

	init_request_hdr(hdr, MODE_POOL4, OP_FOREACH, false);
	payload->foreach.proto = proto;
	payload->foreach.offset_set = false;
	memset(&payload->foreach.offset, 0, sizeof(payload->foreach.offset));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		result = netlink_request(sk, iname, &request, sizeof(request),
				pool4_foreach_response, &args);
		if (result.error)
			return result;
	} while (args.request->foreach.offset_set);

	return result_success();
}

struct jool_result pool4_add(struct jool_socket *sk, char *iname,
		struct pool4_entry_usr *entry)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_ADD, false);
	payload->add = *entry;

	return netlink_request(sk, iname, request, sizeof(request), NULL, NULL);
}

struct jool_result pool4_rm(struct jool_socket *sk, char *iname,
		struct pool4_entry_usr *entry, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_REMOVE, false);
	payload->rm.entry = *entry;
	payload->rm.quick = quick;

	return netlink_request(sk, iname, request, sizeof(request), NULL, NULL);
}

struct jool_result pool4_flush(struct jool_socket *sk, char *iname, bool quick)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_pool4 *payload = (union request_pool4 *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_POOL4, OP_FLUSH, false);
	payload->flush.quick = quick;

	return netlink_request(sk, iname, &request, sizeof(request), NULL, NULL);
}
