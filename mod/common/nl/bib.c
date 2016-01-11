#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/bib/static_routes.h"

static enum config_mode command = MODE_BIB;

static int bib_entry_to_userspace(struct bib_entry *entry, void *arg)
{
	struct nl_core_buffer *buffer = (struct nl_core_buffer *) arg;

	struct bib_entry_usr entry_usr;

	entry_usr.addr4 = entry->ipv4;
	entry_usr.addr6 = entry->ipv6;
	entry_usr.is_static = entry->is_static;

	return nl_core_write_to_buffer(buffer, (__u8*)&entry_usr, sizeof(entry_usr));
}

static int handle_bib_display(struct genl_info *info, struct request_bib *request)
{
	struct nl_core_buffer *buffer;
	struct ipv4_transport_addr *addr4;
	int error;

	log_debug("Sending BIB to userspace.");

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (error)
		return nl_core_respond_error(info, command, error);

	addr4 = request->display.addr4_set ? &request->display.addr4 : NULL;
	error = bibdb_foreach(request->l4_proto, bib_entry_to_userspace, buffer, addr4);
	buffer->pending_data = error > 0 ? true : false;
	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);



	nl_core_free_buffer(buffer);
	return error;
}

static int handle_bib_count(struct genl_info *info, struct request_bib *request)
{
	int error = 0;
	__u64 count;
	struct nl_core_buffer *buffer;

	log_debug("Returning BIB count.");
	error = bibdb_count(request->l4_proto, &count);

	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_new_core_buffer(&buffer, sizeof(count));

	if (error)
		return nl_core_respond_error(info, command, error);

	error = nl_core_write_to_buffer(buffer, (__u8*)&count, sizeof(count));
    error =  (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);

    nl_core_free_buffer(buffer);
    return error;

}

int handle_bib_config(struct genl_info *info)
{
	struct request_hdr *jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);
	struct request_bib *request = (struct request_bib *) (jool_hdr + 1);

	int error = 0;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have BIBs.");
		return -EINVAL;
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_bib_display(info, request);

	case OP_COUNT:

		return handle_bib_count(info, request);

	case OP_ADD:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Adding BIB entry.");
		error = add_static_route(request);

		if (error)
			goto throw_error;

		break;
	case OP_REMOVE:
		if (verify_superpriv()) {
			error = -EPERM;
			goto throw_error;
		}

		log_debug("Removing BIB entry.");
		error = delete_static_route(request);

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
