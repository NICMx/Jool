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
	enum jool_stat_id id;
	unsigned int written;
	int error;

	log_debug("Returning stats.");

	error = request_handle_start(info, XT_ANY, &jool);
	if (error)
		goto end;

	id = 0;
	if (info->attrs[JNLAR_OFFSET_U8]) {
		id = nla_get_u8(info->attrs[JNLAR_OFFSET_U8]);
		log_debug("Offset: [%u]", id);
	}

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

	written = 0;
	for (id++; id <= JSTAT_UNKNOWN; id++) {
#if LINUX_VERSION_AT_LEAST(4, 7, 0, 7, 4)
		error = nla_put_u64_64bit(response.skb, id, stats[id], JSTAT_PADDING);
#else
		error = nla_put_u64(response.skb, id, stats[id]);
#endif
		if (error) {
			if (!written)
				goto revert_response;
			jresponse_enable_m(&response);
			break;
		}

		written++;
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
