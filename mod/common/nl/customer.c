#include "nat64/mod/common/nl/customer.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/pool4/customer.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/db.h"

static int customer_table_to_usr(struct customer_entry_usr *table, void *arg)
{
	return nlbuffer_write(arg, table, sizeof(*table));
}

static int handle_customer_display(struct pool4 *pool, struct genl_info *info,
		union request_customer *request)
{
	struct nlcore_buffer buffer;
	int error = 0;

	log_debug("Sending customer table to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	error = customerdb_foreach(pool, customer_table_to_usr, &buffer);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_customer_add(struct pool4 *pool, struct genl_info *info,
		union request_customer *request)
{
	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Adding elements to customer table.");
	return nlcore_respond(info, customerdb_add(pool, &request->add));
}

static int __handle_customer_rm(struct xlator *jool, struct genl_info *info, bool quick)
{
	struct ipv4_range range;
	int error;

	error = customerdb_rm(jool->nat64.pool4, &range);

	if (!error && !quick) {
		bib_rm_range(jool->nat64.bib, L4PROTO_TCP, &range);
		bib_rm_range(jool->nat64.bib, L4PROTO_ICMP, &range);
		bib_rm_range(jool->nat64.bib, L4PROTO_UDP, &range);
	}

	return nlcore_respond(info, error);
}

static int handle_customer_rm(struct xlator *jool, struct genl_info *info,
		union request_customer *request)
{
	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Removing elements from customer table.");

	return __handle_customer_rm(jool, info, request->rm.quick);
}

static int handle_customer_flush(struct xlator *jool, struct genl_info *info,
		union request_customer *request)
{
	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Flushing customer table.");

	return __handle_customer_rm(jool, info, request->flush.quick);
}

int handle_customer_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	union request_customer *request = (union request_customer *)(hdr + 1);
	int error;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have customer.");
		return nlcore_respond(info, -EINVAL);
	}

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_customer_display(jool->nat64.pool4, info, request);
	case OP_ADD:
		return handle_customer_add(jool->nat64.pool4, info, request);
	case OP_REMOVE:
		return handle_customer_rm(jool, info, request);
	case OP_FLUSH:
		return handle_customer_flush(jool, info, request);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
