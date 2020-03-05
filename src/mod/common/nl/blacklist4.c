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
	struct sk_buff *skb = arg;
	int error;

	error = jnla_put_prefix4(skb, EA_PREFIX4, prefix);
	if (error)
		return (error != -EMSGSIZE) ? -1 : 1;

	return 0;
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
	if (info->attrs[RA_BL4_ENTRY]) {
		error = jnla_get_prefix4(info->attrs[RA_BL4_ENTRY], "Blacklist4 prefix", &offset);
		if (error)
			goto revert_response;
		offset_ptr = &offset;
	}

	error = pool_foreach(jool.siit.blacklist4, serialize_bl4_entry,
			response.skb, offset_ptr);
	if (error < 0) {
		jresponse_cleanup(&response);
		goto revert_response;
	}

	if (error > 0)
		jresponse_enable_m(&response);
	request_handle_end(&jool);
	return jresponse_send(&response);

revert_response:
	jresponse_cleanup(&response);
revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
}

int handle_blacklist4_add(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct ipv4_prefix addend;
	int error;

	log_debug("Adding Blacklist4 entry.");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;

	if (!info->attrs[RA_BL4_ENTRY]) {
		log_err("Request is missing the Blacklist4 container attribute.");
		error = -EINVAL;
		goto revert_start;
	}

	error = jnla_get_prefix4(info->attrs[RA_BL4_ENTRY], "Blacklist4 entry", &addend);
	if (error)
		goto revert_start;

	error = pool_add(jool.siit.blacklist4, &addend,
			get_jool_hdr(info)->flags & HDRFLAGS_FORCE);
	/* Fall through */

revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
}

int handle_blacklist4_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct ipv4_prefix rem; /* TODO */
	int error;

	log_debug("Removing Blacklist4 entry.");

	error = request_handle_start(info, XT_SIIT, &jool);
	if (error)
		goto end;

	if (!info->attrs[RA_BL4_ENTRY]) {
		log_err("Request is missing the Blacklist4 container attribute.");
		error = -EINVAL;
		goto revert_start;
	}

	error = jnla_get_prefix4(info->attrs[RA_BL4_ENTRY], "Blacklist4 entry", &rem);
	if (error)
		goto revert_start;

	error = pool_rm(jool.siit.blacklist4, &rem);
revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
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
	return nlcore_respond(info, error);
}
