#include "mod/common/nl/session.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/bib/db.h"

static int parse_offset(struct nlattr *root, struct session_foreach_offset *entry)
{
	struct nlattr *attrs[SEA_COUNT];
	int error;

	error = nla_parse_nested(attrs, SEA_MAX, root, session_entry_policy, NULL);
	if (error) {
		log_err("The 'session entry' attribute is malformed.");
		return error;
	}

	memset(entry, 0, sizeof(*entry));

	if (attrs[SEA_SRC4]) {
		error = jnla_get_taddr4(attrs[SEA_SRC4], "IPv4 source address", &entry->offset.src);
		if (error)
			return error;
	}
	if (attrs[SEA_DST4]) {
		error = jnla_get_taddr4(attrs[SEA_DST4], "IPv4 destination address", &entry->offset.dst);
		if (error)
			return error;
	}

	entry->include_offset = false;
	return 0;
}

static int serialize_session_entry(struct session_entry const *entry, void *arg)
{
	struct session_entry_usr entry_usr;
	unsigned long dying_time;

	entry_usr.src6 = entry->src6;
	entry_usr.dst6 = entry->dst6;
	entry_usr.src4 = entry->src4;
	entry_usr.dst4 = entry->dst4;
	entry_usr.proto = entry->proto;
	entry_usr.state = entry->state;

	dying_time = entry->update_time + entry->timeout;
	dying_time = (dying_time > jiffies)
			? jiffies_to_msecs(dying_time - jiffies)
			: 0;
	entry_usr.dying_time = (dying_time > U32_MAX) ? U32_MAX : dying_time;

	return jnla_put_session(arg, LA_ENTRY, &entry_usr) ? 1 : 0;
}

int handle_session_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct jool_response response;
	struct session_foreach_offset offset, *offset_ptr;
	l4_protocol proto;
	int error;

	log_debug("Sending session to userspace.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;
	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	if (info->attrs[RA_OFFSET]) {
		error = parse_offset(info->attrs[RA_OFFSET], &offset);
		if (error)
			goto revert_response;
		offset_ptr = &offset;
	}

	proto = info->attrs[RA_PROTO]
			? nla_get_u8(info->attrs[RA_PROTO])
			: 0;

	error = bib_foreach_session(&jool, proto, serialize_session_entry,
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
