#include "nat64/mod/common/nl/pool4.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/db.h"

static int pool4_to_usr(struct pool4_sample *sample, void *arg)
{
	return nlbuffer_write(arg, sample, sizeof(*sample));
}

static int handle_pool4_display(struct pool4 *pool, struct genl_info *info,
		union request_pool4 *request)
{
	struct nlcore_buffer buffer;
	struct pool4_sample *offset = NULL;
	int error = 0;

	log_debug("Sending pool4 to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	if (request->display.offset_set)
		offset = &request->display.offset;

	error = pool4db_foreach_sample(pool, request->display.proto,
			pool4_to_usr, &buffer, offset);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_pool4_add(struct pool4 *pool, struct genl_info *info,
		union request_pool4 *request)
{
	int error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Adding elements to pool4.");

	error = pool4db_add_usr(pool, &request->add.entry);
	return nlcore_respond(info, error);
}

static int handle_pool4_rm(struct xlator *jool, struct genl_info *info,
		union request_pool4 *request)
{
	int error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Removing elements from pool4.");

	error = pool4db_rm_usr(jool->nat64.pool4, &request->rm.entry);

	if (xlat_is_nat64() && !request->rm.quick) {
		bib_rm_range(jool->nat64.bib, request->rm.entry.proto,
				&request->rm.entry.range);
	}

	return nlcore_respond(info, error);
}

static int handle_pool4_flush(struct xlator *jool, struct genl_info *info,
		union request_pool4 *request)
{
	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Flushing pool4.");

	pool4db_flush(jool->nat64.pool4);
	if (xlat_is_nat64() && !request->flush.quick) {
		/*
		 * This will also clear *previously* orphaned entries, but given
		 * that "not quick" generally means "please clean up", this is
		 * more likely what people wants.
		 */
		bib_flush(jool->nat64.bib);
	}

	return nlcore_respond(info, 0);
}

int handle_pool4_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	union request_pool4 *request = (union request_pool4 *)(hdr + 1);
	int error;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have pool4.");
		return nlcore_respond(info, -EINVAL);
	}

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_pool4_display(jool->nat64.pool4, info, request);
	case OP_ADD:
		return handle_pool4_add(jool->nat64.pool4, info, request);
	case OP_REMOVE:
		return handle_pool4_rm(jool, info, request);
	case OP_FLUSH:
		return handle_pool4_flush(jool, info, request);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
