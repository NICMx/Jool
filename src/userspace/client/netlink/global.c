#include "global.h"

#include "common-global.h"
#include "netlink.h"

static int handle_query_response(struct jnl_response *response, void *arg)
{
	struct full_config *config = response->payload;

	if (response->payload_len != sizeof(*config)) {
		log_err("Jool's response has a bogus length. (expected %zu, got %zu)",
				sizeof(*config), response->payload_len);
		return -EINVAL;
	}

	memcpy(arg, config, sizeof(*config));
	return 0;
}

int global_query(struct full_config *result)
{
	return jnl_single_request(MODE_GLOBAL, OP_DISPLAY, NULL, 0,
			handle_query_response, result);
}

int global_update(unsigned int field_index, void *value)
{
	struct global_field *fields;
	size_t field_size;
	size_t total_size;
	struct request_global_update *request;
	int error;

	get_global_fields(&fields, NULL);

	field_size = fields[field_index].type->size;
	total_size = sizeof(struct request_global_update) + field_size;
	request = malloc(total_size);
	if (!request)
		return -ENOMEM;
	request->type = field_index;
	memcpy(request + 1, value, field_size);

	error = jnl_single_request(MODE_GLOBAL, OP_UPDATE, request, total_size,
			NULL, NULL);

	free(request);
	return error;
}
