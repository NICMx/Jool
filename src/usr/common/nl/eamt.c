#include "usr/common/nl/eamt.h"

#include <errno.h>
#include "common/config.h"
#include "common/str_utils.h"
#include "common/types.h"
#include "usr/common/netlink.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_eamt)

struct foreach_args {
	eamt_foreach_cb cb;
	void *args;
	union request_eamt *request;
};

static int eam_display_response(struct jool_response *response, void *arg)
{
	struct eamt_entry *entries = response->payload;
	struct foreach_args *args = arg;
	__u16 entry_count, i;
	int error;

	entry_count = response->payload_len / sizeof(*entries);

	for (i = 0; i < entry_count; i++) {
		error = args->cb(&entries[i], args->args);
		if (error)
			return error;
	}

	args->request->display.prefix4_set = response->hdr->pending_data;
	if (entry_count > 0) {
		struct eamt_entry *last = &entries[entry_count - 1];
		args->request->display.prefix4 = last->prefix4;
	}
	return 0;
}

int eamt_foreach(char *instance, eamt_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);
	struct foreach_args args;
	int error;

	init_request_hdr(hdr, MODE_EAMT, OP_FOREACH, false);
	payload->display.prefix4_set = false;
	memset(&payload->display.prefix4, 0, sizeof(payload->display.prefix4));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		error = netlink_request(instance, request, sizeof(request),
				eam_display_response, &args);
		if (error)
			return error;
	} while (payload->display.prefix4_set);

	return 0;
}

int eamt_add(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4,
		bool force)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_EAMT, OP_ADD, force);
	payload->add.prefix6 = *p6;
	payload->add.prefix4 = *p4;

	return netlink_request(instance, request, sizeof(request), NULL, NULL);
}

int eamt_rm(char *instance, struct ipv6_prefix *p6, struct ipv4_prefix *p4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_EAMT, OP_REMOVE, false);
	if (p6) {
		payload->rm.prefix6_set = true;
		memcpy(&payload->rm.prefix6, p6, sizeof(*p6));
	} else {
		payload->rm.prefix6_set = false;
		memset(&payload->rm.prefix6, 0, sizeof(payload->rm.prefix6));
	}
	if (p4) {
		payload->rm.prefix4_set = true;
		memcpy(&payload->rm.prefix4, p4, sizeof(*p4));
	} else {
		payload->rm.prefix4_set = false;
		memset(&payload->rm.prefix4, 0, sizeof(payload->rm.prefix4));
	}

	return netlink_request(instance, request, sizeof(request), NULL, NULL);
}

int eamt_flush(char *iname)
{
	struct request_hdr request;
	init_request_hdr(&request, MODE_EAMT, OP_FLUSH, false);
	return netlink_request(iname, &request, sizeof(request), NULL, NULL);
}
