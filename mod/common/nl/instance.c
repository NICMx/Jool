#include "nat64/mod/common/nl/instance.h"

#include "nat64/mod/common/types.h"
#include "nat64/mod/common/xlator.h"
#include "nat64/mod/common/nl/nl_common.h"
#include "nat64/mod/common/nl/nl_core2.h"

int handle_instance_add(struct genl_info *info)
{
	return nlcore_respond(info, xlator_add());
}

int handle_instance_rm(struct genl_info *info)
{
	return nlcore_respond(info, xlator_rm());
}

int handle_instance_request(struct genl_info *info)
{
	struct request_hdr *jool_hdr = get_jool_hdr(info);

	if (verify_superpriv())
		return nlcore_respond(info, -EPERM);

	switch (jool_hdr->operation) {
	case OP_ADD:
		return handle_instance_add(info);
	case OP_REMOVE:
		return handle_instance_rm(info);
	}

	log_err("Unknown operation: %d", jool_hdr->operation);
	return nlcore_respond_error(info, -EINVAL);
}
