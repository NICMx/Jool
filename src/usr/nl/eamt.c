#include "eamt.h"

#include <errno.h>

#include "jool_socket.h"

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(union request_eamt)

struct foreach_args {
	eamt_foreach_cb cb;
	void *args;
	union request_eamt *request;
};

static struct jool_result eam_foreach_response(struct jool_response *response,
		void *arg)
{
	struct eamt_entry *entries = response->payload;
	struct foreach_args *args = arg;
	__u16 entry_count, i;
	struct jool_result result;

	entry_count = response->payload_len / sizeof(*entries);

	for (i = 0; i < entry_count; i++) {
		result = args->cb(&entries[i], args->args);
		if (result.error)
			return result;
	}

	args->request->foreach.prefix4_set = response->hdr->pending_data;
	if (entry_count > 0) {
		struct eamt_entry *last = &entries[entry_count - 1];
		args->request->foreach.prefix4 = last->prefix4;
	}
	return result_success();
}

struct jool_result eamt_foreach(struct jool_socket *sk, char *iname,
		eamt_foreach_cb cb, void *_args)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);
	struct foreach_args args;
	struct jool_result result;

	init_request_hdr(hdr, sk->xt, MODE_EAMT, OP_FOREACH, false);
	payload->foreach.prefix4_set = false;
	memset(&payload->foreach.prefix4, 0, sizeof(payload->foreach.prefix4));

	args.cb = cb;
	args.args = _args;
	args.request = payload;

	do {
		result = netlink_request(sk, iname,
				request, sizeof(request),
				eam_foreach_response, &args);
		if (result.error)
			return result;
	} while (payload->foreach.prefix4_set);

	return result_success();
}

struct jool_result eamt_add(struct jool_socket *sk, char *iname,
		struct ipv6_prefix *p6, struct ipv4_prefix *p4, bool force)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_EAMT, OP_ADD, force);
	payload->add.prefix6 = *p6;
	payload->add.prefix4 = *p4;

	return netlink_request(sk, iname, request, sizeof(request), NULL, NULL);
}

struct jool_result eamt_rm(struct jool_socket *sk, char *iname,
		struct ipv6_prefix *p6, struct ipv4_prefix *p4)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_EAMT, OP_REMOVE, false);
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

	return netlink_request(sk, iname, request, sizeof(request), NULL, NULL);
}

struct jool_result eamt_flush(struct jool_socket *sk, char *iname)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	init_request_hdr(hdr, sk->xt, MODE_EAMT, OP_FLUSH, false);
	return netlink_request(sk, iname, request, sizeof(request), NULL, NULL);
}

static struct jool_result bad_len(size_t expected, size_t actual)
{
	return result_from_error(
		-EINVAL,
		"Jool's response has a bogus length. (expected %zu, got %zu).",
		expected, actual
	);
}

static struct jool_result eam_query64_response(struct jool_response *response,
		void *args)
{
	if (response->payload_len < sizeof(struct in_addr))
		return bad_len(sizeof(struct in_addr), response->payload_len);

	*((struct in_addr *)args) = *((struct in_addr *)response->payload);
	return result_success();
}

struct jool_result eamt_query_v6(struct jool_socket *sk, char *iname,
		struct in6_addr *in, struct in_addr *out)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_EAMT, OP_TEST, false);
	payload->test.proto = 6;
	payload->test.addr.v6 = *in;

	return netlink_request(sk, iname, request, sizeof(request),
			eam_query64_response, out);
}

static struct jool_result eam_query46_response(struct jool_response *response,
		void *args)
{
	if (response->payload_len < sizeof(struct in6_addr))
		return bad_len(sizeof(struct in6_addr), response->payload_len);

	*((struct in6_addr *)args) = *((struct in6_addr *)response->payload);
	return result_success();
}

struct jool_result eamt_query_v4(struct jool_socket *sk, char *iname,
		struct in_addr *in, struct in6_addr *out)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	union request_eamt *payload = (union request_eamt *)(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_EAMT, OP_TEST, false);
	payload->test.proto = 4;
	payload->test.addr.v4 = *in;

	return netlink_request(sk, iname, request, sizeof(request),
			eam_query46_response, out);
}
