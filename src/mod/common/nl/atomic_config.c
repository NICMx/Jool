#include "mod/common/nl/atomic_config.h"

#include "mod/common/log.h"
#include "mod/common/atomic_config.h"
#include "mod/common/nl/nl_common.h"

int handle_atomconfig_request(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	LOG_DEBUG("Handling atomic configuration request.");

	error = __jnl_start(&state, info, XT_ANY, true);
	if (error)
		return jnl_reply(state, error);

	return jnl_reply(state, atomconfig_add(state, info));
}
