#include "usr/common/nl/global.h"

#include <errno.h>
#include "common/common-global.h"
#include "common/types.h"
#include "usr/common/str_utils.h"
#include "usr/common/netlink.h"

int global_query_response(struct jool_response *response, void *args)
{
	struct globals *config = response->payload;

	if (response->payload_len != sizeof(*config)) {
		log_err("Jool's response has a bogus length. (expected %zu, got %zu).",
				sizeof(*config), response->payload_len);
		log_err("This is probably a programming error.");
		return -EINVAL;
	}

	memcpy(args, config, sizeof(struct globals));
	return 0;
}

int global_query(char *iname, struct globals *result)
{
	struct request_hdr request;
	init_request_hdr(&request, MODE_GLOBAL, OP_FOREACH, false);
	return netlink_request(iname, &request, sizeof(request),
			global_query_response, result);
}

int global_update(char *iname, struct global_field *field, void *value,
		bool force)
{
	struct request_hdr *hdr;
	struct global_value *meta;
	void *payload;
	size_t value_size;
	size_t total_size;
	int result;

	/*
	 * BTW: We're not validating @field.
	 * Consider that if you ever plan on releasing this as a library.
	 * Update: kernelspace has validation functions.
	 */

	value_size = field->type->size;
	total_size = sizeof(struct request_hdr)
			+ sizeof(struct global_value)
			+ value_size;

	hdr = malloc(total_size);
	if (!hdr)
		return -ENOMEM;
	meta = (struct global_value *)(hdr + 1);
	payload = meta + 1;

	init_request_hdr(hdr, MODE_GLOBAL, OP_UPDATE, force);
	meta->type = global_field_index(field);
	meta->len = value_size;
	memcpy(payload, value, value_size);

	result = netlink_request(iname, hdr, total_size, NULL, NULL);

	free(hdr);
	return result;
}
