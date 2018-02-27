#include "nl/nl-session.h"

#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nat64/bib/db.h"

static int session_entry_to_userspace(struct session_entry *entry, void *arg)
{
	struct jnl_buffer *buffer = (struct jnl_buffer *) arg;
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

	return jnlbuffer_write(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_session_foreach(struct bib *db,
		struct globals *globals,
		struct genl_info *info,
		struct request_session_foreach *request)
{
	struct jnl_buffer buffer;
	struct session_foreach_func func = {
			.cb = session_entry_to_userspace,
			.arg = &buffer,
	};
	struct session_foreach_offset offset_struct;
	struct session_foreach_offset *offset = NULL;
	int error;

	if (verify_privileges())
		return jnl_respond(info, -EPERM);

	log_debug("Sending session table to userspace.");

	error = jnlbuffer_init(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return jnl_respond(info, error);

	if (request->offset_set) {
		offset_struct.offset = request->offset;
		offset_struct.include_offset = false;
		offset = &offset_struct;
	}

	error = bib_foreach_session(db, globals, request->l4_proto, &func, offset);
	jnlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? jnlbuffer_send(&buffer, info)
			: jnl_respond(info, error);

	jnlbuffer_free(&buffer);
	return error;
}

int handle_session_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	void *payload = get_jool_payload(info);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_FOREACH:
		return handle_session_foreach(jool->bib, &jool->global->cfg,
				info, payload);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return jnl_respond(info, -EINVAL);
}
