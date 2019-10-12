#include "address.h"

#include <errno.h>

#define HDR_LEN sizeof(struct request_hdr)
#define PAYLOAD_LEN sizeof(struct request_addrxlat)

static struct jool_result query_response_cb(size_t expected_len,
		struct jool_response *response, void *args)
{
	if (expected_len != response->payload_len) {
		return result_from_error(
			-EINVAL,
			"Jool's response has a bogus length. (expected %zu, got %zu).",
			expected_len,
			response->payload_len
		);
	}

	memcpy(args, response->payload, expected_len);
	return result_success();
}

static struct jool_result query64_response_cb(struct jool_response *response,
		void *args)
{
	return query_response_cb(sizeof(struct result_addrxlat64),
			response, args);
}

static struct jool_result query46_response_cb(struct jool_response *response,
		void *args)
{
	return query_response_cb(sizeof(struct result_addrxlat46),
			response, args);
}

struct jool_result address_query64(struct jool_socket *sk, char *iname,
		struct in6_addr *addr, struct result_addrxlat64 *result)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_addrxlat *payload = (struct request_addrxlat *)
			(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_ADDRESS, OP_TEST, false);
	payload->direction = 64;
	payload->addr.v6 = *addr;

	return netlink_request(sk, iname, request, sizeof(request),
			query64_response_cb, result);
}

struct jool_result address_query46(struct jool_socket *sk, char *iname,
		struct in_addr *addr, struct result_addrxlat46 *result)
{
	unsigned char request[HDR_LEN + PAYLOAD_LEN];
	struct request_hdr *hdr = (struct request_hdr *)request;
	struct request_addrxlat *payload = (struct request_addrxlat *)
			(request + HDR_LEN);

	init_request_hdr(hdr, sk->xt, MODE_ADDRESS, OP_TEST, false);
	payload->direction = 46;
	payload->addr.v4 = *addr;

	return netlink_request(sk, iname, request, sizeof(request),
			query46_response_cb, result);
}
