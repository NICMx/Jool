#include "mod/common/nl/stats.h"

#include "mod/common/stats.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"

static int handle_stats_query(struct xlator *jool, struct genl_info *info)
{
	__u64 *result;
	int error;

	log_debug("Returning stats.");

	result = jstat_query(jool->stats);
	if (!result)
		return nlcore_respond(info, -ENOMEM);

	error = nlcore_respond_struct(info, result,
			__JSTAT_MAX * sizeof(*result));

	kfree(result);
	return error;
}

int handle_stats_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	switch (hdr->operation) {
	case OP_FOREACH:
		return handle_stats_query(jool, info);
	}

	log_err("Unknown operation: %u", hdr->operation);
	return nlcore_respond(info, -EINVAL);
}
