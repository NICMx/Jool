#include "mod/common/nl/fmr.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/fmr.h"

static int serialize_fmr_entry(struct mapping_rule const *entry, void *arg)
{
	struct config_mapping_rule rule;

	if (entry) {
		rule.set = true;
		rule.rule = *entry;
	} else {
		rule.set = false;
		memset(&rule.rule, 0, sizeof(rule.rule));
	}

	return jnla_put_mapping_rule(arg, JNLAL_ENTRY, &rule) ? 1 : 0;
}

int handle_fmrt_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct jool_response response;
	struct ipv4_prefix offset, *offset_ptr;
	int error;

	error = request_handle_start(info, XT_MAPT, &jool, true);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Sending FMR table to userspace.");

	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	offset_ptr = NULL;
	if (info->attrs[JNLAR_OFFSET]) {
		error = jnla_get_prefix4(info->attrs[JNLAR_OFFSET],
				"Iteration offset", &offset);
		if (error)
			goto revert_response;
		offset_ptr = &offset;
		__log_debug(&jool, "Offset: [%pI4/%u]", &offset.addr,
				offset.len);
	}

	error = fmrt_foreach(jool.mapt.fmrt, serialize_fmr_entry, response.skb,
			offset_ptr);
	if (error < 0) {
		log_err("Offset not found.");
		jresponse_cleanup(&response);
		goto revert_response;
	}

	error = jresponse_send_array(&jool, &response, error);
	if (error)
		goto revert_response;

	request_handle_end(&jool);
	return 0;

revert_response:
	jresponse_cleanup(&response);
revert_start:
	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}

int handle_fmrt_add(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct config_mapping_rule addend;
	int error;

	error = request_handle_start(info, XT_MAPT, &jool, true);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Adding FMR entry.");

	error = jnla_get_mapping_rule(info->attrs[JNLAR_OPERAND], "Operand", &addend);
	if (error)
		goto revert_start;
	if (!addend.set) {
		log_err("Request contains an empty FMR.");
		error = -EINVAL;
		goto revert_start;
	}

	error = fmrt_add(jool.mapt.fmrt, &addend.rule);
revert_start:
	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}

int handle_fmrt_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct config_mapping_rule subtrahend;
	int error;

	error = request_handle_start(info, XT_MAPT, &jool, true);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Removing FMR entry.");

	error = jnla_get_mapping_rule(info->attrs[JNLAR_OPERAND], "Operand", &subtrahend);
	if (error)
		goto revert_start;
	if (!subtrahend.set) {
		log_err("Request contains an empty FMR.");
		error = -EINVAL;
		goto revert_start;
	}

	error = fmrt_rm(jool.mapt.fmrt, &subtrahend.rule);
revert_start:
	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}

int handle_fmrt_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	error = request_handle_start(info, XT_MAPT, &jool, true);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Flushing FMR table.");

	fmrt_flush(jool.mapt.fmrt);

	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}
