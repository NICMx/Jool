#include "mod/common/nl/pool4.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/pool4/db.h"
#include "mod/common/db/bib/db.h"

static int serialize_pool4_entry(struct pool4_entry const *entry, void *arg)
{
	return jnla_put_pool4(arg, JNLAL_ENTRY, entry) ? 1 : 0;
}

int handle_pool4_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct jool_response response;
	struct pool4_entry offset, *offset_ptr;
	int error;

	log_debug("Sending pool4 to userspace.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;
	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	if (info->attrs[JNLAR_OFFSET]) {
		error = jnla_get_pool4(info->attrs[JNLAR_OFFSET], "Iteration offset", &offset);
		if (error)
			goto revert_response;
		offset_ptr = &offset;
	} else if (info->attrs[JNLAR_PROTO]) {
		offset.proto = nla_get_u8(info->attrs[JNLAR_PROTO]);
		offset_ptr = NULL;
	} else {
		log_err("The request is missing a protocol.");
		error = -EINVAL;
		goto revert_response;
	}

	error = pool4db_foreach_sample(jool.nat64.pool4,
			offset.proto, serialize_pool4_entry, response.skb,
			offset_ptr);

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

int handle_pool4_add(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct pool4_entry entry;
	int error;

	log_debug("Adding elements to pool4.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	error = jnla_get_pool4(info->attrs[JNLAR_OPERAND], "Operand", &entry);
	if (error)
		goto revert_start;

	error = pool4db_add(jool.nat64.pool4, &entry);
revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

/*
int handle_pool4_update(struct sk_buff *skb, struct genl_info *info)
{
	log_debug("Updating pool4 table.");
	return nlcore_respond(info, pool4db_update(pool, &request->update));
}
*/

int handle_pool4_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct pool4_entry entry;
	int error;

	log_debug("Removing elements from pool4.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	error = jnla_get_pool4(info->attrs[JNLAR_OPERAND], "Operand", &entry);
	if (error)
		goto revert_start;

	error = pool4db_rm_usr(jool.nat64.pool4, &entry);
	if (xlator_is_nat64(&jool) && !(get_jool_hdr(info)->flags & JOOLNLHDR_FLAGS_QUICK))
		bib_rm_range(&jool, entry.proto, &entry.range);

revert_start:
	request_handle_end(&jool);
end:
	return jresponse_send_simple(info, error);
}

int handle_pool4_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	int error;

	log_debug("Flushing pool4.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	pool4db_flush(jool.nat64.pool4);
	if (xlator_is_nat64(&jool) && !(get_jool_hdr(info)->flags & JOOLNLHDR_FLAGS_QUICK)) {
		/*
		 * This will also clear *previously* orphaned entries, but given
		 * that "not quick" generally means "please clean up," this is
		 * more likely what people wants.
		 */
		bib_flush(&jool);
	}

	request_handle_end(&jool);
end:	return jresponse_send_simple(info, error);
}
