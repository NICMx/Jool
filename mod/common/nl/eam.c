#include "nat64/mod/common/types.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateless/eam.h"

static enum config_mode command = MODE_EAMT;

static int eam_entry_to_userspace(struct eamt_entry *entry, void *arg) {

	struct nl_core_buffer *buffer = (struct nl_core_buffer *) arg;
	return nl_core_write_to_buffer(buffer, (__u8*)entry, sizeof(*entry));

}

static int handle_eamt_display(struct genl_info *info, union request_eamt *request) {

	struct nl_core_buffer *buffer;
	struct ipv4_prefix *prefix4;
	int error;

	log_debug("Sending EAMT to userspace.");

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (error)
		 nl_core_respond_error(info, command, error);

	prefix4 = request->display.prefix4_set ? &request->display.prefix4 : NULL;
	error = eamt_foreach(eam_entry_to_userspace, buffer, prefix4);
	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);

	nl_core_free_buffer(buffer);

	return error;
}

static int handle_eamt_count(struct genl_info *info) {
	__u64 count;
	int error;
	struct nl_core_buffer *buffer;

	log_debug("Returning EAMT count.");

	error = eamt_count(&count);
	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_new_core_buffer(&buffer, sizeof(count));

	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_write_to_buffer(buffer, (__u8*)&count, sizeof(count));

	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);

	nl_core_free_buffer(buffer);

	return error;

}

int handle_eamt_config(struct genl_info *info) {
	struct request_hdr *jool_hdr = info->userhdr;
	union request_eamt *request = (union request_eamt *)(jool_hdr + 1);

	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have an EAMT.");
		return -EINVAL;
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_eamt_display(info, request);

	case OP_COUNT:
		return handle_eamt_count(info);

	case OP_ADD:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Adding EAMT entry.");
		error = eamt_add(&request->add.prefix6, &request->add.prefix4, request->add.force);

		if (error)
			goto throw_error;

		break;
	case OP_REMOVE:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Removing EAMT entry.");
		error = eamt_rm(request->rm.prefix6_set ? &request->rm.prefix6 : NULL,
						request->rm.prefix4_set ? &request->rm.prefix4 : NULL);

		if (error)
			goto throw_error;

		break;
	case OP_FLUSH:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		eamt_flush();

		break;
	default:
		log_err("Unknown operation: %d", jool_hdr->operation);
		return nl_core_respond_error(info, command, -EINVAL);
	}

	return 0;

	throw_error:
	return nl_core_respond_error(info, command, error);

}
