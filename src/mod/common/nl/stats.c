#include "mod/common/nl/stats.h"

#include "mod/common/log.h"
#include "mod/common/stats.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"

int handle_stats_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	__u64 *stats;
	struct jool_response response;
	int i, error;

	log_debug("Returning stats.");

	error = request_handle_start(info, XT_ANY, &jool);
	if (error)
		goto end;

	/* Perform query */
	stats = jstat_query(jool.stats);
	if (!stats) {
		error = -ENOMEM;
		goto revert_start;
	}

	/* Build response */
	error = jresponse_init(&response, info);
	if (error)
		goto revert_query;
	for (i = 1; i <= JSTAT_UNKNOWN; i++) {
		error = nla_put_u64_64bit(response.skb, i, stats[i], JSTAT_PADDING);
		if (error)
			goto revert_response;
	}

	/* Send response */
	kfree(stats);
	request_handle_end(&jool);
	return jresponse_send(&response);

revert_response:
	report_put_failure();
	jresponse_cleanup(&response);
revert_query:
	kfree(stats);
revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}
