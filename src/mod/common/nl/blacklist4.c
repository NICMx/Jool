#include "mod/common/nl/blacklist4.h"

#include "common/types.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/pool.h"

static int serialize_bl4_entry(struct ipv4_prefix *prefix, void *arg)
{
	return jnla_put_prefix4(arg, JNLAL_ENTRY, prefix) ? 1 : 0;
}

int handle_blacklist4_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct jool_response response;
	struct ipv4_prefix offset, *offset_ptr;
	int error;

	log_debug("Sending the blacklist4 to userspace.");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;
	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	offset_ptr = NULL;
	if (info->attrs[JNLAR_OFFSET]) {
		error = jnla_get_prefix4(info->attrs[JNLAR_OFFSET], "Iteration offset", &offset);
		if (error)
			goto revert_response;
		offset_ptr = &offset;
		log_debug("Offset: [%pI4/%u]", &offset.addr, offset.len);
	}

	error = pool_foreach(jool.siit.blacklist4, serialize_bl4_entry,
			response.skb, offset_ptr);

	error = jresponse_send_array(&response, error);
	if (error)
		goto revert_response;

	request_handle_end(&jool);
	return 0;

revert_response:
	jresponse_cleanup(&response);
revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int handle_blacklist4_add(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct ipv4_prefix operand;
	int error;

	log_debug("Adding Blacklist4 entry.");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;

	error = jnla_get_prefix4(info->attrs[JNLAR_OPERAND], "Operand", &operand);
	if (error)
		goto revert_start;

	error = pool_add(jool.siit.blacklist4, &operand,
			get_jool_hdr(info)->flags & JOOLNLHDR_FLAGS_FORCE);
	/* Fall through */

revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int handle_blacklist4_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct ipv4_prefix operand;
	int error;

	log_debug("Removing Blacklist4 entry.");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;

	error = jnla_get_prefix4(info->attrs[JNLAR_OPERAND], "Operand", &operand);
	if (error)
		goto revert_start;

	error = pool_rm(jool.siit.blacklist4, &operand);
revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int handle_blacklist4_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	log_debug("Flushing the blacklist4...");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;

	error = pool_flush(jool.siit.blacklist4);
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}
