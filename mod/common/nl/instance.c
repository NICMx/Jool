#include "nat64/mod/common/nl/instance.h"

#include "nat64/common/types.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"

static int xlator_entry_to_userspace(struct xlator const *entry, void *arg)
{
	struct nlcore_buffer *buffer = (struct nlcore_buffer *)arg;
	struct instance_entry_usr entry_usr;

	entry_usr.ns = entry->ns;
	entry_usr.fw = entry->fw;
	strcpy(entry_usr.iname, entry->iname);

	return nlbuffer_write(buffer, &entry_usr, sizeof(entry_usr));
}

static int handle_instance_display(struct genl_info *info,
		union request_instance *request)
{
	struct nlcore_buffer buffer;
	struct instance_entry_usr *offset;
	int error;

	log_debug("Sending instance table to userspace.");

	error = nlbuffer_init_response(&buffer, info, nlbuffer_response_max_size());
	if (error)
		return nlcore_respond(info, error);

	offset = request->display.offset_set ? &request->display.offset : NULL;
	error = xlator_foreach(xlator_entry_to_userspace, &buffer, offset);
	nlbuffer_set_pending_data(&buffer, error > 0);
	error = (error >= 0)
			? nlbuffer_send(info, &buffer)
			: nlcore_respond(info, error);

	nlbuffer_clean(&buffer);
	return error;
}

static int handle_instance_add(struct genl_info *info,
		union request_instance *request)
{
	log_debug("Adding Jool instance.");

	return nlcore_respond(info, xlator_add(
			request->add.fw,
			request->add.iname,
			NULL
	));
}

static int handle_instance_rm(struct genl_info *info,
		union request_instance *request)
{
	log_debug("Removing Jool instance.");

	return nlcore_respond(info, xlator_rm(
			request->rm.fw,
			request->rm.iname
	));
}

int handle_instance_request(struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	union request_instance *request = (union request_instance *)(hdr + 1);

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_DISPLAY:
		return handle_instance_display(info, request);
	case OP_ADD:
		return handle_instance_add(info, request);
	case OP_REMOVE:
		return handle_instance_rm(info, request);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
