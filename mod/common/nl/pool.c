#include "nat64/mod/stateless/rfc6791.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/common/nl/nl_common.h"

static enum config_mode command = MODE_RFC6791;

static int pool_to_usr(struct ipv4_prefix *prefix, void *arg)
{
	return nl_core_write_to_buffer(arg, (__u8*)prefix, sizeof(*prefix));
}

static int handle_pool6791_display(struct genl_info *info, union request_pool *request)
{
	struct nl_core_buffer *buffer;
	struct ipv4_prefix *offset;
	int error = 0;

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (error)
		return nl_core_respond_error(info, command, error);

	offset = request->display.offset_set ? &request->display.offset : NULL;

	error = rfc6791_for_each(pool_to_usr, buffer, offset);

	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer)  : nl_core_respond_error(info, command, error);

	nl_core_free_buffer(buffer);

	return error;
}

static int handle_pool6791_count(struct genl_info *info)
{
	int error = 0;
	__u64 count;
	struct nl_core_buffer *buffer;

	error = nl_core_new_core_buffer(&buffer, sizeof(count));

	if (error)
		goto throw_error;

	error = rfc6791_count(&count);

	if (error)
		goto throw_error_with_deallocation;

	error = nl_core_send_buffer(info, command, buffer);

	if (error)
		goto throw_error_with_deallocation;

	nl_core_free_buffer(buffer);

	return 0;

	throw_error_with_deallocation:
	nl_core_free_buffer(buffer);
	throw_error:
	return nl_core_respond_error(info, command, error);
}

int handle_rfc6791_config(struct genl_info *info)
{
	struct request_hdr *jool_hdr = info->userhdr;
	union request_pool *request = (union request_pool *)jool_hdr + 1;

	int error;

	if (xlat_is_nat64()) {
		log_err("RFC 6791 does not apply to Stateful NAT64.");
		return -EINVAL;
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		log_debug("Sending RFC6791 pool to userspace.");
		return handle_pool6791_display(info, request);

	case OP_COUNT:
		log_debug("Returning address count in the RFC6791 pool.");
		return handle_pool6791_count(info);

	case OP_ADD:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Adding an address to the RFC6791 pool.");
		error = rfc6791_add(&request->add.addrs);

		if (error)
			goto throw_error;

		break;
	case OP_REMOVE:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Removing an address from the RFC6791 pool.");
		error = rfc6791_rm(&request->rm.addrs);

		if (error)
			goto throw_error;

		break;
	case OP_FLUSH:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Flushing the RFC6791 pool...");
		error = rfc6791_flush();

		if (error)
			goto throw_error;

		break;
	default:
		log_err("Unknown operation: %d", jool_hdr->operation);
		error = -EINVAL;
		goto throw_error;
	}

	nl_core_send_acknowledgement(info, command);
	return 0;

	throw_error:
		return nl_core_respond_error(info, command, error);
}
