#include "usr/common/nl/bib.h"

#include <errno.h>
#include "common/config.h"
#include "common/str_utils.h"
#include "common/types.h"
#include "usr/common/dns.h"
#include "usr/common/netlink.h"
#include "usr/common/userspace-types.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_bib)

struct foreach_args {
	bib_foreach_cb cb;
	void *args;
	struct request_bib *request;
};

static int bib_foreach_response(struct jool_response *response, void *arg)
{
	struct bib_entry_usr *entries = response->payload;
	struct foreach_args *args = arg;
	unsigned int entry_count;
	unsigned int e;
	int error;

	entry_count = response->payload_len / sizeof(*entries);

	for (e = 0; e < entry_count; e++) {
		error = args->cb(&entries[e], args->args);
		if (error)
			return error;
	}

	args->request->display.addr4_set = response->hdr->pending_data;
	if (entry_count > 0)
		args->request->display.addr4 = entries[entry_count - 1].addr4;

	return 0;
}

int bib_foreach(char *iname, l4_protocol proto,
		bib_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);
	struct foreach_args args;
	bool error;

	init_request_hdr(hdr, MODE_BIB, OP_FOREACH, false);
	payload->l4_proto = proto;
	payload->display.addr4_set = false;
	memset(&payload->display.addr4, 0, sizeof(payload->display.addr4));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		error = netlink_request(iname, request, sizeof(request),
				bib_foreach_response, &args);
	} while (!error && payload->display.addr4_set);

	return error;
}

int bib_add(char *iname,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_BIB, OP_ADD, false);
	payload->l4_proto = proto;
	payload->add.addr6 = *a6;
	payload->add.addr4 = *a4;

	return netlink_request(iname, request, sizeof(request), NULL, NULL);
}

int bib_rm(char *iname,
		struct ipv6_transport_addr *a6,
		struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);

	init_request_hdr(hdr, MODE_BIB, OP_REMOVE, false);
	payload->l4_proto = proto;
	if (a6) {
		payload->rm.addr6_set = true;
		memcpy(&payload->rm.addr6, a6, sizeof(*a6));
	} else {
		payload->rm.addr6_set = false;
		memset(&payload->rm.addr6, 0, sizeof(payload->rm.addr6));
	}
	if (a4) {
		payload->rm.addr4_set = true;
		memcpy(&payload->rm.addr4, a4, sizeof(*a4));
	} else {
		payload->rm.addr4_set = false;
		memset(&payload->rm.addr4, 0, sizeof(payload->rm.addr4));
	}

	return netlink_request(iname, request, sizeof(request), NULL, NULL);
}
