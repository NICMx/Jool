#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/bib/db.h"

static enum config_mode command = MODE_POOL4;

static int pool4_to_usr(struct pool4_sample *sample, void *arg)
{
	return nl_core_write_to_buffer(arg,(__u8 *)sample, sizeof(*sample));
}

static int handle_pool4_display(struct genl_info *info, union request_pool4 *request)
{
	struct nl_core_buffer *buffer;
	struct pool4_sample *offset = NULL;
	int error = 0;

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (error)
		return nl_core_respond_error(info, command, error);

	if (request->display.offset_set)
		offset = &request->display.offset;

	error = pool4db_foreach_sample(pool4_to_usr, buffer, offset);
	buffer->pending_data = error > 0 ? true : false;
	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) :  nl_core_respond_error(info, command, error);


	nl_core_free_buffer(buffer);
	return error;
}

static int handle_pool4_add(struct genl_info *info, union request_pool4 *request)
{
	int error = 0;

	if (verify_superpriv())
		return nl_core_respond_error(info, command, -EPERM);

	log_debug("Adding elements to the IPv4 pool.");

	error = pool4db_add(request->add.mark,
			request->add.proto, &request->add.addrs,
			&request->add.ports);

	if (error)
		return nl_core_respond_error(info, command, error);

	return 0;
}

static int handle_pool4_rm(struct genl_info *info, union request_pool4 *request)
{
	int error = 0;

	if (verify_superpriv())
		return nl_core_respond_error(info, command, -EPERM);

	log_debug("Removing elements from the IPv4 pool.");

	error = pool4db_rm(request->rm.mark, request->rm.proto,
			&request->rm.addrs, &request->rm.ports);

	if (xlat_is_nat64() && !request->rm.quick) {
		sessiondb_delete_taddr4s(&request->rm.addrs, &request->rm.ports);
		bibdb_delete_taddr4s(&request->rm.addrs, &request->rm.ports);
	}

	if (error)
		return nl_core_respond_error(info, command, error);

	return 0;
}

static int handle_pool4_flush(struct genl_info *info, union request_pool4 *request)
{
	int error;

	if (verify_superpriv())
		return nl_core_respond_error(info, command, -EPERM);

	log_debug("Flushing the IPv4 pool...");
	error = pool4db_flush();

	/*
	 * Well, pool4db_flush only errors on memory allocation failures,
	 * so I guess clearing BIB and session even if pool4db_flush fails
	 * is a good idea.
	 */
	if (xlat_is_nat64() && !request->flush.quick) {
		sessiondb_flush();
		bibdb_flush();
	}

	if (error)
		return nl_core_respond_error(info, command, error);

	return 0;
}

static int handle_pool4_count(struct genl_info *info)
{
	int error = 0;
	struct response_pool4_count counters;
	struct nl_core_buffer *buffer;

	log_debug("Returning IPv4 pool counters.");
			pool4db_count(&counters.tables, &counters.samples,
					&counters.taddrs);

	error = nl_core_new_core_buffer(&buffer, sizeof(counters));

	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_write_to_buffer(buffer,(__u8 *)&counters, sizeof(counters));

	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);

	nl_core_free_buffer(buffer);

	return error;
}

int handle_pool4_config(struct genl_info *info)
{
	struct request_hdr *jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);
	union request_pool4 *request = (union request_pool4 *) (jool_hdr + 1);


	if (xlat_is_siit()) {
		log_err("SIIT doesn't have pool4.");
		return -EINVAL;
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_pool4_display(info, request);

	case OP_COUNT:
		return handle_pool4_count(info);

	case OP_ADD:
		 handle_pool4_add(info, request);
		 break;
	case OP_REMOVE:
		handle_pool4_rm(info, request);
		break;

	case OP_FLUSH:
		handle_pool4_flush(info, request);
		break;

	default:

		log_err("Unknown operation: %d", jool_hdr->operation);
		return nl_core_respond_error(info, command, -EINVAL);
	}

	return nl_core_send_acknowledgement(info, command);

}
