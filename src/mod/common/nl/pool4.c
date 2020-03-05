#include "mod/common/nl/pool4.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/pool4/db.h"
#include "mod/common/db/bib/db.h"

static int parse_pool4_entry(struct nlattr *root, struct pool4_entry *entry)
{
	struct nlattr *attrs[P4A_COUNT];
	int error;

	error = nla_parse_nested(attrs, P4A_MAX, root, pool4_entry_policy, NULL);
	if (error) {
		log_err("The 'pool4 entry' attribute is malformed.");
		return error;
	}

	memset(entry, 0, sizeof(*entry));

	if (attrs[P4A_MARK])
		entry->mark = nla_get_u32(attrs[P4A_MARK]);
	if (attrs[P4A_ITERATIONS])
		entry->iterations = nla_get_u32(attrs[P4A_ITERATIONS]);
	if (attrs[P4A_FLAGS])
		entry->flags = nla_get_u8(attrs[P4A_FLAGS]);
	if (attrs[P4A_PROTO])
		entry->proto = nla_get_u8(attrs[P4A_PROTO]);
	if (attrs[P4A_PREFIX]) {
		error = jnla_get_prefix4(attrs[P4A_PREFIX], "IPv4 prefix", &entry->range.prefix);
		if (error)
			return error;
	}
	if (attrs[P4A_PORT_MIN])
		entry->range.ports.min = nla_get_u16(attrs[P4A_PORT_MIN]);
	if (attrs[P4A_PORT_MAX])
		entry->range.ports.max = nla_get_u16(attrs[P4A_PORT_MAX]);

	return 0;
}

static int serialize_pool4_entry(struct pool4_entry const *entry, void *arg)
{
	struct sk_buff *skb = arg;
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, RA_POOL4_ENTRY);
	if (!root)
		return 1;

	error = nla_put_u32(skb, P4A_MARK, entry->mark)
		|| nla_put_u32(skb, P4A_ITERATIONS, entry->iterations)
		|| nla_put_u8(skb, P4A_FLAGS, entry->flags)
		|| nla_put_u8(skb, P4A_PROTO, entry->proto)
		|| jnla_put_prefix4(skb, P4A_PREFIX, &entry->range.prefix)
		|| nla_put_u16(skb, P4A_PORT_MIN, entry->range.ports.min)
		|| nla_put_u16(skb, P4A_PORT_MAX, entry->range.ports.max);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return 1;
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

	if (info->attrs[RA_POOL4_ENTRY]) {
		error = parse_pool4_entry(info->attrs[RA_POOL4_ENTRY], &offset);
		if (error)
			goto revert_response;
		offset_ptr = &offset;
	} else if (info->attrs[RA_PROTO]) {
		offset.proto = nla_get_u8(info->attrs[RA_PROTO]);
		offset_ptr = NULL;
	} else {
		log_err("The request is missing a protocol.");
		error = -EINVAL;
		goto revert_response;
	}

	error = pool4db_foreach_sample(jool.nat64.pool4,
			offset.proto, serialize_pool4_entry, response.skb,
			offset_ptr);
	if (error < 0) {
		jresponse_cleanup(&response);
		goto revert_response;
	}

	if (error > 0)
		jresponse_enable_m(&response);
	return jresponse_send(&response);

revert_response:
	jresponse_cleanup(&response);
revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
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

	if (!info->attrs[RA_POOL4_ENTRY]) {
		log_err("Request is missing the pool4 container attribute.");
		error = -EINVAL;
		goto revert_start;
	}

	error = parse_pool4_entry(info->attrs[RA_POOL4_ENTRY], &entry);
	if (error)
		goto revert_start;

	error = pool4db_add(jool.nat64.pool4, &entry);
revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
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

	if (!info->attrs[RA_POOL4_ENTRY]) {
		log_err("Request is missing the pool4 container attribute.");
		error = -EINVAL;
		goto revert_start;
	}

	error = parse_pool4_entry(info->attrs[RA_POOL4_ENTRY], &entry);
	if (error)
		goto revert_start;

	error = pool4db_rm_usr(jool.nat64.pool4, &entry);
	if (xlator_is_nat64(&jool) && !(get_jool_hdr(info)->flags & HDRFLAGS_QUICK))
		bib_rm_range(&jool, entry.proto, &entry.range);

revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
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
	if (xlator_is_nat64(&jool) && !(get_jool_hdr(info)->flags & HDRFLAGS_QUICK)) {
		/*
		 * This will also clear *previously* orphaned entries, but given
		 * that "not quick" generally means "please clean up," this is
		 * more likely what people wants.
		 */
		bib_flush(&jool);
	}

	request_handle_end(&jool);
end:	return nlcore_respond(info, error);
}
