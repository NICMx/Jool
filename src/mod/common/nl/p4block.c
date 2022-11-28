#include "mod/common/nl/p4block.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/pool4-v2/block.h"

int handle_p4block_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	error = request_handle_start(info, XT_NAT64, &jool, true);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Printing p4blocks on the log.");

	p4block_print(jool.nat64.blocks, NULL);

	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}

int handle_p4block_add(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct p4block addend;
	int error;

	error = request_handle_start(info, XT_NAT64, &jool, true);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Adding p4block entry.");

	error = jnla_get_p4block(info->attrs[JNLAR_OPERAND], "Operand", &addend);
	if (error)
		goto revert_start;

	error = p4block_add(jool.nat64.blocks, &addend);
revert_start:
	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}

int handle_p4block_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct p4block subtrahend;
	int error;

	error = request_handle_start(info, XT_NAT64, &jool, true);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Removing p4block entry.");

	error = jnla_get_p4block(info->attrs[JNLAR_OPERAND], "Operand", &subtrahend);
	if (error)
		goto revert_start;

	error = p4block_rm(jool.nat64.blocks, &subtrahend);
revert_start:
	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}
