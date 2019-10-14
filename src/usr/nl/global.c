#include "global.h"

#include <errno.h>

#include "jool_socket.h"

static struct jool_result global_query_response(struct jool_response *response,
		void *args)
{
	struct globals *config = response->payload;

	if (response->payload_len != sizeof(*config)) {
		return result_from_error(
			-EINVAL,
			"Jool's response has a bogus length. (expected %zu, got %zu).",
			sizeof(*config), response->payload_len
		);
	}

	memcpy(args, config, sizeof(struct globals));
	return result_success();
}

struct jool_result global_query(struct jool_socket *sk, char *iname,
		struct globals *out)
{
	struct request_hdr request;
	init_request_hdr(&request, sk->xt, MODE_GLOBAL, OP_FOREACH, false);
	return netlink_request(sk, iname, &request, sizeof(request),
			global_query_response, out);
}

struct jool_result global_update(struct jool_socket *sk, char *iname,
		struct global_field *field, void *value, bool force)
{
	struct request_hdr *hdr;
	struct global_value *meta;
	void *payload;
	size_t value_size;
	size_t total_size;
	struct jool_result result;

	/*
	 * TODO (warning) BTW: We're not validating @field.
	 * Update: kernelspace has validation functions.
	 */

	value_size = field->type->size;
	total_size = sizeof(struct request_hdr)
			+ sizeof(struct global_value)
			+ value_size;

	hdr = malloc(total_size);
	if (!hdr)
		return result_from_enomem();
	meta = (struct global_value *)(hdr + 1);
	payload = meta + 1;

	init_request_hdr(hdr, sk->xt, MODE_GLOBAL, OP_UPDATE, force);
	meta->type = global_field_index(field);
	meta->len = value_size;
	memcpy(payload, value, value_size);

	result = netlink_request(sk, iname, hdr, total_size, NULL, NULL);

	free(hdr);
	return result;
}
