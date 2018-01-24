#include "nat64/mod/common/nl/timestamp.h"

#include "nat64/common/config.h"
#include "nat64/mod/common/timestamp.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"

static int timestamp_to_userspace(struct timestamps_entry_usr *entry, void *arg)
{
	return nlbuffer_write(arg, entry, sizeof(*entry));
}

static int handle_global_display(struct genl_info *info)
{
	struct nlcore_buffer buffer;
	struct timestamp_foreach_func func = {
			.cb = timestamp_to_userspace,
			.arg = &buffer,
	};
	size_t msg_size;
	int error;

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	log_debug("Sending timestamps to userspace.");

	log_info("Note: Our maximum NL message size is %zu bytes.",
			nlbuffer_response_max_size());
	log_info("Each timestamp group is %zu bytes long.",
			TST_LENGTH * sizeof(struct timestamps_entry_usr));

	msg_size = TS_BATCH_COUNT * TST_LENGTH * sizeof(struct timestamps_entry_usr);
	if (msg_size > nlbuffer_response_max_size()) {
		log_err("The timestamps do not fit in a netlink message. More programming is required.");
		return nlcore_respond(info, -EINVAL);
	}

	error = nlbuffer_init_response(&buffer, info, msg_size);
	if (error)
		return nlcore_respond(info, error);

	error = timestamp_foreach(&func, &buffer);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_free(&buffer);
	return error;
}

int handle_timestamp(struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_global_display(info);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
