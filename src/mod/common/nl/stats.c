#include "mod/common/nl/stats.h"

#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/stats.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"

int handle_stats_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	__u64 *stats;
	enum jool_stat_id id;
	unsigned int written;
	int error;

	error = jnl_start(&state, info, XT_ANY, false);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Returning stats.");

	id = 0;
	if (info->attrs[JNLAR_OFFSET_U8]) {
		id = nla_get_u8(info->attrs[JNLAR_OFFSET_U8]);
		jnls_debug(state, "Offset: [%u]", id);
	}

	/* Perform query */
	stats = jstat_query(jnls_xlator(state)->stats);
	if (!stats)
		return jnl_reply(state, -ENOMEM);

	/* Build response */
	written = 0;
	for (id++; id <= JSTAT_UNKNOWN; id++) {
#if LINUX_VERSION_AT_LEAST(4, 7, 0, 7, 4)
		error = nla_put_u64_64bit(jnls_skb(state), id, stats[id],
				JSTAT_PADDING);
#else
		error = nla_put_u64(jnls_skb(state), id, stats[id]);
#endif
		if (error) {
			if (!written) {
				kfree(stats);
				return jnl_reply(state, error);
			}
			jnls_enable_m(state);
			break;
		}

		written++;
	}

	/* Send response */
	kfree(stats);
	return jnl_reply(state, error);
}
