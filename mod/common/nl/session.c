#include "nat64/mod/common/nl/session.h"

#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"
#include "nat64/mod/stateful/bib/db.h"

static int session_entry_to_userspace(struct session_entry *entry, void *arg)
{
	struct nlcore_buffer *buffer = (struct nlcore_buffer *) arg;
	struct session_entry_usr entry_usr;
	unsigned long dying_time;

	entry_usr.src6 = entry->src6;
	entry_usr.dst6 = entry->dst6;
	entry_usr.src4 = entry->src4;
	entry_usr.dst4 = entry->dst4;
	entry_usr.state = entry->state;

	dying_time = entry->update_time + entry->timeout;
	entry_usr.dying_time = (dying_time > jiffies)
			? jiffies_to_msecs(dying_time - jiffies)
			: 0;

	return nlbuffer_write(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_session_display(struct bib *db, struct genl_info *info,
		struct request_session *request)
{
	struct nlcore_buffer buffer;
	struct session_foreach_func func = {
			.cb = session_entry_to_userspace,
			.arg = &buffer,
	};
	struct session_foreach_offset offset_struct;
	struct session_foreach_offset *offset = NULL;
	int error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Sending session table to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	if (request->display.offset_set) {
		offset_struct.offset = request->display.offset;
		offset_struct.include_offset = false;
		offset = &offset_struct;
	}

	error = bib_foreach_session(db, request->l4_proto, &func, offset);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

static int handle_session_count(struct bib *db, struct genl_info *info,
		struct request_session *request)
{
	int error;
	__u64 count;

	log_debug("Returning session count.");

	error = bib_count_sessions(db, request->l4_proto, &count);
	if (error)
		return nlcore_respond(info, error);

	return nlcore_respond_struct(info, &count, sizeof(count));
}

int handle_session_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr;
	struct request_session *request;
	int error;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have session tables.");
		return nlcore_respond(info, -EINVAL);
	}

	hdr = get_jool_hdr(info);
	request = (struct request_session *)(hdr + 1);

	error = validate_request_size(info, sizeof(*request));
	if (error)
		return nlcore_respond(info, error);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_session_display(jool->nat64.bib, info, request);
	case OP_COUNT:
		return handle_session_count(jool->nat64.bib, info, request);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
