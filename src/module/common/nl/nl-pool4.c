#include "nl/nl-pool4.h"

#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

static int pool4_to_usr(struct pool4_sample *sample, void *arg)
{
	return nlbuffer_write(arg, sample, sizeof(*sample));
}

static int handle_pool4_foreach(struct pool4 *pool, struct genl_info *info,
		struct request_pool4_foreach *request)
{
	struct nlcore_buffer buffer;
	struct pool4_sample *offset = NULL;
	int error;

	log_debug("Sending pool4 to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	if (request->offset_set)
		offset = &request->offset;

	error = pool4db_foreach_sample(pool, request->proto,
			pool4_to_usr, &buffer, offset);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_pool4_add(struct pool4 *pool, struct genl_info *info,
		struct request_pool4_add *request)
{
	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	log_debug("Adding elements to pool4.");
	return nlcore_respond(info, pool4db_add(pool, &request->entry));
}

/*
static int handle_pool4_update(struct pool4 *pool, struct genl_info *info,
		struct request_pool4 *request)
{
	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	log_debug("Updating pool4 table.");
	return nlcore_respond(info, pool4db_update(pool, &request->update));
}
*/

static int handle_pool4_rm(struct xlator *jool, struct genl_info *info,
		struct request_pool4_rm *request)
{
	int error;

	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	log_debug("Removing elements from pool4.");

	error = pool4db_rm_usr(jool->pool4, &request->entry);

	if (!request->quick) {
		bib_rm_range(jool->bib, request->entry.proto,
				&request->entry.range);
	}

	return nlcore_respond(info, error);
}

static int handle_pool4_flush(struct xlator *jool, struct genl_info *info,
		struct request_pool4_flush *request)
{
	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	log_debug("Flushing pool4.");

	pool4db_flush(jool->pool4);
	if (!request->quick) {
		/*
		 * This will also clear *previously* orphaned entries, but given
		 * that "not quick" generally means "please clean up", this is
		 * more likely what people wants.
		 */
		bib_flush(jool->bib);
	}

	return nlcore_respond(info, 0);
}

int handle_pool4_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	void *payload = get_jool_payload(info);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_pool4_foreach(jool->pool4, info, payload);
	case OP_ADD:
		return handle_pool4_add(jool->pool4, info, payload);
	/*
	case OP_UPDATE:
		return handle_pool4_update(jool->pool4, info, payload);
	 */
	case OP_REMOVE:
		return handle_pool4_rm(jool, info, payload);
	case OP_FLUSH:
		return handle_pool4_flush(jool, info, payload);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
