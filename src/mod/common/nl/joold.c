#include "mod/common/nl/joold.h"

#include "mod/common/log.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/joold.h"

int handle_joold_add(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Handling joold add.");

	error = joold_sync(state, info->attrs[JNLAR_SESSION_ENTRIES]);
	if (error)
		return jnl_reply(state, error);

	/*
	 * Do not bother userspace with an ACK; it's not
	 * waiting nor has anything to do with it.
	 */
	jnl_cancel(state);
	return 0;
}

int handle_joold_advertise(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Handling joold advertise.");

	return jnl_reply(state, joold_advertise(state));
}

int handle_joold_ack(struct sk_buff *skb, struct genl_info *info)
{
	struct jnl_state *state;
	int error;

	error = jnl_start(&state, info, XT_NAT64, true);
	if (error)
		return jnl_reply(state, error);

	jnls_debug(state, "Handling joold ack.");

	joold_ack(state);
	return 0; /* Do not ack the ack. */
}
