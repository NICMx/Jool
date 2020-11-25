#include "mod/common/nl/fmr.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/fmr.h"

static int serialize_fmr_entry(struct mapping_rule const *entry, void *arg)
{
	return jnla_put_fmr(arg, JNLAL_ENTRY, entry) ? 1 : 0;
}

int handle_fmrt_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct jool_response response;
	struct ipv4_prefix offset, *offset_ptr;
	int error;

	error = request_handle_start(info, XT_MAPT, &jool);
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
	struct mapping_rule addend;
	int error;

	error = request_handle_start(info, XT_MAPT, &jool);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Adding FMR entry.");

	error = jnla_get_fmr(info->attrs[JNLAR_OPERAND], "Operand", &addend);
	if (error)
		goto revert_start;

	error = fmrt_add(jool.mapt.fmrt, &addend);
revert_start:
	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}

int handle_fmrt_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	error = request_handle_start(info, XT_MAPT, &jool);
	if (error)
		return jresponse_send_simple(NULL, info, error);

	__log_debug(&jool, "Flushing FMR table.");

	fmrt_flush(jool.mapt.fmrt);

	error = jresponse_send_simple(&jool, info, error);
	request_handle_end(&jool);
	return error;
}
