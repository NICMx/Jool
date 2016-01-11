#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateless/blacklist4.h"

static enum config_mode command = MODE_BLACKLIST;

static int pool_to_usr(struct ipv4_prefix *prefix, void *arg)
{
	return nl_core_write_to_buffer(arg, (__u8 *)prefix, sizeof(*prefix));
}

static int handle_blacklist_display(struct genl_info *info, union request_pool *request)
{
	struct nl_core_buffer *buffer;
	struct ipv4_prefix *offset;
	int error = 0;

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (error)
		return nl_core_respond_error(info, command, error);

	offset = request->display.offset_set ? &request->display.offset : NULL;
	error = blacklist_for_each(pool_to_usr, buffer, offset);
	buffer->pending_data = error > 0 ? true : false;
	error = (error >= 0) ?  nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);


	nl_core_free_buffer(buffer);
	return error;

}

static int handle_blacklist_count(struct genl_info *info)
{
	__u64 count;
	int error = 0;
	struct nl_core_buffer *buffer;

	log_debug("Returning address count in the Blacklist pool.");
	error = blacklist_count(&count);

	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_write_to_buffer(buffer, (__u8 *)&count, sizeof(count));

	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info,command,error);

	nl_core_free_buffer(buffer);

	return error;


}

int handle_blacklist_config(struct genl_info *info)
{
	struct request_hdr *jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);
	union request_pool *request = (union request_pool *) (jool_hdr + 1);
	int error = 0;

	if (xlat_is_nat64()) {
		log_err("Blacklist does not apply to Stateful NAT64.");
		return -EINVAL;
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending Blacklist pool to userspace.");
		return handle_blacklist_display(info ,request);

	case OP_COUNT:

		return handle_blacklist_count(info);

	case OP_ADD:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Adding an address to the Blacklist pool.");

		error = blacklist_add(&request->add.addrs);

		if (error)
			goto throw_error;

		break;
	case OP_REMOVE:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Removing an address from the Blacklist pool.");
		error = blacklist_rm(&request->rm.addrs);

		if (error)
			goto throw_error;

		break;
	case OP_FLUSH:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Flushing the Blacklist pool...");
		error = blacklist_flush();

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
	return 	nl_core_respond_error(info,command,error);
}
