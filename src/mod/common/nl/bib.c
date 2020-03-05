#include "mod/common/nl/bib.h"

#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"
#include "mod/common/db/pool4/db.h"
#include "mod/common/db/bib/db.h"

static int parse_bib_entry(struct nlattr *root, struct bib_entry *entry)
{
	struct nlattr *attrs[BA_COUNT];
	int error;

	error = nla_parse_nested(attrs, BA_MAX, root, bib_entry_policy, NULL);
	if (error) {
		log_err("The 'BIB entry' attribute is malformed.");
		return error;
	}

	memset(entry, 0, sizeof(*entry));

	if (attrs[BA_SRC6]) {
		error = jnla_get_taddr6(attrs[BA_SRC6], "IPv6 transport address", &entry->addr6);
		if (error)
			return error;
	}
	if (attrs[BA_SRC4]) {
		error = jnla_get_taddr4(attrs[BA_SRC4], "IPv4 transport address", &entry->addr4);
		if (error)
			return error;
	}
	if (attrs[BA_PROTO])
		entry->l4_proto = nla_get_u8(attrs[BA_PROTO]);
	if (attrs[BA_STATIC])
		entry->is_static = nla_get_u8(attrs[BA_STATIC]);

	return 0;
}

static int serialize_bib_entry(struct bib_entry const *entry, void *arg)
{
	struct sk_buff *skb = arg;
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, RA_BIB_ENTRY);
	if (!root)
		return 1;

	error = jnla_put_taddr6(skb, BA_SRC6, &entry->addr6)
		|| jnla_put_taddr4(skb, BA_SRC4, &entry->addr4)
		|| nla_put_u8(skb, BA_PROTO, entry->l4_proto)
		|| nla_put_u8(skb, BA_STATIC, entry->is_static);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return 1;
}

int handle_bib_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct jool_response response;
	struct bib_entry offset, *offset_ptr;
	int error;

	log_debug("Sending BIB to userspace.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;
	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	if (info->attrs[RA_BIB_ENTRY]) {
		error = parse_bib_entry(info->attrs[RA_BIB_ENTRY], &offset);
		if (error)
			goto revert_response;
		offset_ptr = &offset;
	} else if (info->attrs[RA_PROTO]) {
		offset.l4_proto = nla_get_u8(info->attrs[RA_PROTO]);
		offset_ptr = NULL;
	} else {
		log_err("The request is missing a protocol.");
		error = -EINVAL;
		goto revert_response;
	}

	/* TODO stop fooling around and receive the full BIB as offset. */
	error = bib_foreach(jool.nat64.bib, offset.l4_proto, serialize_bib_entry,
			response.skb, offset_ptr ? &offset_ptr->addr4 : NULL);
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

int handle_bib_add(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct bib_entry new;
	int error;

	log_debug("Adding BIB entry.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	if (!info->attrs[RA_BIB_ENTRY]) {
		log_err("The request lacks a BIB container attribute.");
		error = -EINVAL;
		goto revert_start;
	}

	error = parse_bib_entry(info->attrs[RA_BIB_ENTRY], &new);
	if (error)
		goto revert_start;

	if (!pool4db_contains(jool.nat64.pool4, jool.ns, new.l4_proto, &new.addr4)) {
		log_err("The transport address '%pI4#%u' does not belong to pool4.\n"
				"Please add it there first.",
				&new.addr4.l3, new.addr4.l4);
		goto revert_start;
	}

	error = bib_add_static(&jool, &new);
revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);
}

int handle_bib_rm(struct sk_buff *skb, struct genl_info *info)
{
	struct xlator jool;
	struct nlattr *attrs[BA_COUNT];
	struct bib_entry entry;
	int error;

	log_debug("Removing BIB entry.");

	error = request_handle_start(info, XT_NAT64, &jool);
	if (error)
		goto end;

	if (!info->attrs[RA_BIB_ENTRY]) {
		log_err("The request lacks a BIB container attribute.");
		error = -EINVAL;
		goto revert_start;
	}

	error = nla_parse_nested(attrs, BA_MAX, info->attrs[RA_BIB_ENTRY], bib_entry_policy, NULL);
	if (error) {
		log_err("The 'BIB entry' attribute is malformed.");
		goto revert_start;
	}

	if (!attrs[BA_SRC6] && !attrs[BA_SRC4]) {
		error = -EINVAL;
		goto revert_start;
	}

	if (attrs[BA_SRC6]) {
		error = jnla_get_taddr6(attrs[BA_SRC6], "IPv6 transport address", &entry.addr6);
		if (error)
			goto revert_start;
	}
	if (attrs[BA_SRC4]) {
		error = jnla_get_taddr4(attrs[BA_SRC4], "IPv4 transport address", &entry.addr4);
		if (error)
			goto revert_start;
	}

	if (attrs[BA_PROTO])
		entry.l4_proto = nla_get_u8(attrs[BA_PROTO]);
	if (attrs[BA_STATIC])
		entry.is_static = nla_get_u8(attrs[BA_STATIC]);

	if (!attrs[BA_SRC4])
		error = bib_find6(jool.nat64.bib, entry.l4_proto, &entry.addr6, &entry);
	else if (!attrs[BA_SRC6])
		error = bib_find4(jool.nat64.bib, entry.l4_proto, &entry.addr4, &entry);
	if (error == -ESRCH)
		goto esrch;
	if (error)
		goto revert_start;

	error = bib_rm(&jool, &entry);
	if (error == -ESRCH)
		goto esrch;
	/* Fall through */

revert_start:
	request_handle_end(&jool);
end:
	return nlcore_respond(info, error);

esrch:
	log_err("The entry wasn't in the database.");
	goto revert_start;
}
