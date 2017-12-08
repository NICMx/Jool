#include "nl/nl-instance.h"

#include "types.h"
#include "xlator.h"
#include "nl/nl-common.h"
#include "nl/nl-core.h"

static int handle_instance_add(struct genl_info *info)
{
	log_debug("Adding Jool instance.");
	return nlcore_respond(info, xlator_add(NULL));
}

static int handle_instance_rm(struct genl_info *info)
{
	log_debug("Removing Jool instance.");
	return nlcore_respond(info, xlator_rm());
}

int handle_instance_request(struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_ADD:
		return handle_instance_add(info);
	case OP_REMOVE:
		return handle_instance_rm(info);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
