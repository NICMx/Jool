#include "nat64/mod/common/nl/pool4.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/session/db.h"

static const enum config_mode COMMAND = MODE_POOL4;

static int pool4_to_usr(struct pool4_sample *sample, void *arg)
{
	return nl_core_write_to_buffer(arg, sample, sizeof(*sample));
}

static int handle_pool4_display(struct pool4 *pool, struct genl_info *info,
		union request_pool4 *request)
{
	struct nl_core_buffer *buffer;
	struct pool4_sample *offset = NULL;
	int error = 0;

	log_debug("Sending pool4 to userspace.");

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());
	if (error)
		return nl_core_respond_error(info, COMMAND, error);

	if (request->display.offset_set)
		offset = &request->display.offset;

	error = pool4db_foreach_sample(pool, pool4_to_usr, buffer, offset);
	buffer->pending_data = error > 0;
	error = (error >= 0)
			? nl_core_send_buffer(info, COMMAND, buffer)
			: nl_core_respond_error(info, COMMAND, error);

	nl_core_free_buffer(buffer);
	return error;
}

static int handle_pool4_add(struct pool4 *pool, struct genl_info *info,
		union request_pool4 *request)
{
	int error;

	if (verify_superpriv())
		return nl_core_respond_error(info, COMMAND, -EPERM);

	log_debug("Adding elements to pool4.");

	error = pool4db_add(pool, request->add.mark, request->add.proto,
			&request->add.addrs, &request->add.ports);
	return nlcore_respond(info, COMMAND, error);
}

static int handle_pool4_rm(struct xlator *jool, struct genl_info *info,
		union request_pool4 *request)
{
	int error;

	if (verify_superpriv())
		return nl_core_respond_error(info, COMMAND, -EPERM);

	log_debug("Removing elements from pool4.");

	error = pool4db_rm(jool->nat64.pool4, request->rm.mark,
			request->rm.proto, &request->rm.addrs,
			&request->rm.ports);

	/*
	 * See the respective comment in handle_pool4_flush().
	 * The rationale is more or less the same.
	 */
	if (xlat_is_nat64() && !request->rm.quick) {
		sessiondb_delete_taddr4s(jool->nat64.session,
				&request->rm.addrs, &request->rm.ports);
		bibdb_delete_taddr4s(jool->nat64.bib, &request->rm.addrs,
				&request->rm.ports);
	}

	return nlcore_respond(info, COMMAND, error);
}

static int handle_pool4_flush(struct xlator *jool, struct genl_info *info,
		union request_pool4 *request)
{
	int error;

	if (verify_superpriv())
		return nl_core_respond_error(info, COMMAND, -EPERM);

	log_debug("Flushing pool4.");
	error = pool4db_flush(jool->nat64.pool4);

	/*
	 * Well, pool4db_flush() only errors on memory allocation failures,
	 * so I guess clearing BIB and session even if pool4db_flush fails
	 * is a good idea.
	 */
	if (xlat_is_nat64() && !request->flush.quick) {
		sessiondb_flush(jool->nat64.session);
		bibdb_flush(jool->nat64.bib);
	}

	return nlcore_respond(info, COMMAND, error);
}

static int handle_pool4_count(struct pool4 *pool, struct genl_info *info)
{
	struct response_pool4_count counts;
	log_debug("Returning pool4 counters.");
	pool4db_count(pool, &counts.tables, &counts.samples, &counts.taddrs);
	return nlcore_respond_struct(info, COMMAND, &counts, sizeof(counts));
}

int handle_pool4_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);
	union request_pool4 *request = (union request_pool4 *)(jool_hdr + 1);

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have pool4.");
		return nl_core_respond_error(info, COMMAND, -EINVAL);
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_pool4_display(jool->nat64.pool4, info, request);
	case OP_COUNT:
		return handle_pool4_count(jool->nat64.pool4, info);
	case OP_ADD:
		return handle_pool4_add(jool->nat64.pool4, info, request);
	case OP_REMOVE:
		return handle_pool4_rm(jool, info, request);
	case OP_FLUSH:
		return handle_pool4_flush(jool, info, request);
	}

	log_err("Unknown operation: %d", jool_hdr->operation);
	return nl_core_respond_error(info, COMMAND, -EINVAL);
}
