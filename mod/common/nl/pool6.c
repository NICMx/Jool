#include "nat64/mod/common/types.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateful/session/db.h"

static enum config_mode command = MODE_POOL6;

static int pool6_entry_to_userspace(struct ipv6_prefix *prefix, void *arg)
{
	return nl_core_write_to_buffer(arg, (__u8 *)prefix, sizeof(*prefix));
}

static int handle_pool6_display(struct genl_info *info, union request_pool6 *request)
{
	struct nl_core_buffer *buffer;
	struct ipv6_prefix *prefix;
	int error = 0;

	log_debug("Sending IPv6 pool to userspace.");


	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (error)
		return nl_core_respond_error(info, command, error);

	request->display.prefix_set ? log_info("prefix is set!") : log_info("prefix isn't set!");

	prefix = request->display.prefix_set ? &request->display.prefix : NULL;

	error = pool6_for_each(pool6_entry_to_userspace, buffer, prefix);

	buffer->pending_data = error > 0 ?  true : false;

	error = (error >= 0)  ?  nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);


	nl_core_free_buffer(buffer);



	return error;
}

static int handle_pool6_count(struct genl_info *info)
{
	__u64 count;
	int error = 0;
	struct nl_core_buffer *buffer;

	log_debug("Returning IPv6 prefix count.");
	error = pool6_count(&count);

	if (error)
		return nl_core_respond_error(info, command, error);


	error = nl_core_new_core_buffer(&buffer, sizeof(count));

	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_write_to_buffer(buffer,(__u8 *)&count, sizeof(count));

	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);

	nl_core_free_buffer(buffer);

	return error;
}

int handle_pool6_config(struct genl_info *info)
{
	int error;

	struct request_hdr *jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);
	union request_pool6 *request = (union request_pool6 *) (jool_hdr + 1);


	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		log_info("entering pool6 display!");
		return handle_pool6_display(info, request);

	case OP_COUNT:
		log_info("entering pool6 count!");
		return handle_pool6_count(info);

	case OP_ADD:
	case OP_UPDATE:
		log_info("entering pool6 add, update!");
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Adding a prefix to the IPv6 pool.");

		log_info("prefix integer %lu \n", &request->add.prefix.address);

		error = pool6_add(&request->add.prefix);

		if (error)
			goto throw_error;

		break;
	case OP_REMOVE:
		log_info("entering pool6 add, remove!");
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Removing a prefix from the IPv6 pool.");
		error = pool6_remove(&request->rm.prefix);

		if (error)
			goto throw_error;

		if (xlat_is_nat64() && !request->flush.quick)
			sessiondb_delete_taddr6s(&request->rm.prefix);

		break;
	case OP_FLUSH:
		log_info("entering pool6 add, flush!");
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Flushing the IPv6 pool...");
		error = pool6_flush();

		if (xlat_is_nat64() && !request->flush.quick)
			sessiondb_flush();

		if (error)
			goto throw_error;

		break;
	default:
		log_err("Unknown operation: %d", jool_hdr->operation);
		error = -EINVAL;
		goto throw_error;
	}

	return 0;

	throw_error:
	return nl_core_respond_error(info, command, error);

}
