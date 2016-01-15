#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/common/nl/nl_core2.h"

static enum config_mode command = MODE_SESSION;

static int session_entry_to_userspace(struct session_entry *entry, void *arg)
{
	struct nl_core_buffer *buffer = (struct nl_core_buffer *) arg;
	struct session_entry_usr entry_usr;
	unsigned long dying_time;

	if (!entry->expirer || !entry->expirer->get_timeout)
		return -EINVAL;

	entry_usr.remote6 = entry->remote6;
	entry_usr.local6 = entry->local6;
	entry_usr.local4 = entry->local4;
	entry_usr.remote4 = entry->remote4;
	entry_usr.state = entry->state;

	dying_time = entry->update_time + entry->expirer->get_timeout();
	entry_usr.dying_time = (dying_time > jiffies) ? jiffies_to_msecs(dying_time - jiffies) : 0;

	return nl_core_write_to_buffer(buffer, (__u8 *)&entry_usr, sizeof(entry_usr));
}

static int handle_session_display(struct genl_info *info, struct request_session *request)
{
	struct nl_core_buffer *buffer;
	struct ipv4_transport_addr *remote4 = NULL;
	struct ipv4_transport_addr *local4 = NULL;
	int error = 0;

	log_debug("Sending session table to userspace.");

	error = nl_core_new_core_buffer(&buffer, nl_core_data_max_size());

	if (!buffer)
		return nl_core_respond_error(info, command, error);

	if (request->display.connection_set) {
		remote4 = &request->display.remote4;
		local4 = &request->display.local4;
	}

	error = sessiondb_foreach(request->l4_proto, session_entry_to_userspace, buffer, remote4, local4);
	buffer->pending_data = error > 0 ? true : false;
	error = (error >= 0) ? nl_core_send_buffer(info, command, buffer) : nl_core_respond_error(info, command, error);

	nl_core_free_buffer(buffer);

	return error;
}

static int handle_session_count(struct genl_info *info, struct request_session *request)
{
	int error = 0;
	struct nl_core_buffer *buffer;
	__u64 count;

	error = nl_core_new_core_buffer(&buffer, sizeof(count));
	if (error)
		goto throw_error;

	error = sessiondb_count(request->l4_proto, &count);

	if (error)
		goto throw_error_with_deallocation;

	nl_core_write_to_buffer(buffer, (__u8*) &count, sizeof(count));

	error = nl_core_send_buffer(info, command, buffer);

	if (error)
		goto throw_error_with_deallocation;

	nl_core_free_buffer(buffer);
	log_info("buffer sent!!");

	return 0;

	throw_error_with_deallocation:
	nl_core_free_buffer(buffer);
	throw_error:
	log_info("an error was thrown!");
	return nl_core_respond_error(info, command, error);
}

int handle_session_config(struct genl_info *info)
{

	 struct request_hdr *jool_hdr = (struct request_hdr *) (info->attrs[ATTR_DATA] + 1);
	 struct request_session *request = (struct request_session *) (jool_hdr + 1);

	int error;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have session tables.");
		return -EINVAL;
	}

	switch (jool_hdr->operation) {
	case OP_DISPLAY:
		return handle_session_display(info, request);

	case OP_COUNT:
		log_debug("Returning session count.");
		return handle_session_count(info, request);

	default:
		log_err("Unknown operation: %d", jool_hdr->operation);
		error = -EINVAL;
		return nl_core_respond_error(info, command, error);
	}
}
