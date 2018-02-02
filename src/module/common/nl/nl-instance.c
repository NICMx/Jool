#include "nl/nl-instance.h"

#include "xlator.h"
#include "nl/nl-common.h"
#include "nl/nl-core.h"

static int handle_instance_add(struct genl_info *info,
		struct request_instance_add *request)
{
	log_debug("Adding Jool instance.");
	return nlcore_respond(info, xlator_add(NULL, request->type,
			request->name));
}

static int handle_instance_rm(struct genl_info *info,
		struct request_instance_rm *request)
{
	log_debug("Removing Jool instance.");
	return nlcore_respond(info, xlator_rm(request->name));
}

int handle_instance_request(struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_ADD:
		/*
		 * Yeah, the casting is kind of dumb.
		 * It's because there really is not much point to casting
		 * correctly, and I really don't want to break lines.
		 */
		return handle_instance_add(info, (void *)(hdr + 1));
	case OP_REMOVE:
		return handle_instance_rm(info, (void *)(hdr + 1));
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
