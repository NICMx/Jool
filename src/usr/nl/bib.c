#include "bib.h"

#include <errno.h>

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_bib)

struct foreach_args {
	bib_foreach_cb cb;
	void *args;
	struct request_bib *request;
};

static struct jool_result bib_foreach_response(struct jool_response *response,
		void *arg)
{
	struct bib_entry_usr *entries = response->payload;
	struct foreach_args *args = arg;
	unsigned int entry_count;
	unsigned int e;
	struct jool_result result;

	entry_count = response->payload_len / sizeof(*entries);

	for (e = 0; e < entry_count; e++) {
		result = args->cb(&entries[e], args->args);
		if (result.error)
			return result;
	}

	args->request->foreach.addr4_set = response->hdr->pending_data;
	if (entry_count > 0)
		args->request->foreach.addr4 = entries[entry_count - 1].addr4;

	return result_success();
}

struct jool_result bib_foreach(struct jool_socket *sk, char *iname,
	l4_protocol proto, bib_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);
	struct foreach_args args;
	struct jool_result result;

	init_request_hdr(hdr, sk->xt, MODE_BIB, OP_FOREACH, false);
	payload->l4_proto = proto;
	payload->foreach.addr4_set = false;
	memset(&payload->foreach.addr4, 0, sizeof(payload->foreach.addr4));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		result = netlink_request(sk, iname,
				request, sizeof(request),
				bib_foreach_response, &args);
	} while (!result.error && payload->foreach.addr4_set);

	return result;
}

struct jool_result bib_add(struct jool_socket *sk, char *iname,
		struct ipv6_transport_addr *a6, struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_BIB, OP_ADD, false);
	payload->l4_proto = proto;
	payload->add.addr6 = *a6;
	payload->add.addr4 = *a4;

	return netlink_request(sk, iname, request, sizeof(request), NULL, NULL);
}

struct jool_result bib_rm(struct jool_socket *sk, char *iname,
		struct ipv6_transport_addr *a6, struct ipv4_transport_addr *a4,
		l4_protocol proto)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_bib *payload = (struct request_bib *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_BIB, OP_REMOVE, false);
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

	return netlink_request(sk, iname, request, sizeof(request), NULL, NULL);
}
