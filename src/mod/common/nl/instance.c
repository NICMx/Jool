#include "mod/common/nl/instance.h"

#include "common/types.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"

static int xlator_entry_to_userspace(struct xlator *entry, void *arg)
{
	struct nlcore_buffer *buffer = (struct nlcore_buffer *)arg;
	struct instance_entry_usr entry_usr;

	entry_usr.ns = entry->ns;
	entry_usr.xf = xlator_flags2xf(entry->flags);
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

	offset = request->foreach.offset_set ? &request->foreach.offset : NULL;
	error = xlator_foreach(get_jool_hdr(info)->xt,
			xlator_entry_to_userspace, &buffer, offset);
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
			request->add.xf | get_jool_hdr(info)->xt,
			request->add.iname,
			&request->add.pool6,
			NULL
	));
}

static int handle_instance_hello(struct genl_info *info,
		union request_instance *request)
{
	struct instance_hello_response response;
	int error;

	log_debug("Handling instance Hello.");

	error = xlator_find_current(request->hello.iname,
			XF_ANY | get_jool_hdr(info)->xt, NULL);
	switch (error) {
	case 0:
		response.status = IHS_ALIVE;
		return nlcore_respond_struct(info, &response, sizeof(response));
	case -ESRCH:
		response.status = IHS_DEAD;
		return nlcore_respond_struct(info, &response, sizeof(response));
	}

	return nlcore_respond(info, error);
}

static int handle_instance_rm(struct genl_info *info,
		union request_instance *request)
{
	log_debug("Removing Jool instance.");
	return nlcore_respond(info, xlator_rm(get_jool_hdr(info)->xt,
			request->rm.iname));
}

static int handle_instance_flush(struct genl_info *info,
		union request_instance *request)
{
	log_debug("Flushing all instances from this namespace.");
	return nlcore_respond(info, xlator_flush(get_jool_hdr(info)->xt));
}

int handle_instance_request(struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);
	union request_instance *request = (union request_instance *)(hdr + 1);

	switch (hdr->operation) {
	case OP_FOREACH:
		return handle_instance_display(info, request);
	case OP_TEST:
		return handle_instance_hello(info, request);
	case OP_ADD:
		return handle_instance_add(info, request);
	case OP_REMOVE:
		return handle_instance_rm(info, request);
	case OP_FLUSH:
		return handle_instance_flush(info, request);
	}

	log_err("Unknown operation: %u", hdr->operation);
	return nlcore_respond(info, -EINVAL);
}
