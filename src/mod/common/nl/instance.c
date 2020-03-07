#include "mod/common/nl/instance.h"

#include "common/types.h"
#include "mod/common/log.h"
#include "mod/common/xlator.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core.h"

static int parse_instance(struct nlattr *root, struct instance_entry_usr *entry)
{
	struct nlattr *attrs[IFEA_COUNT];
	int error;

	error = nla_parse_nested(attrs, IFEA_MAX, root, instance_entry_policy, NULL);
	if (error) {
		log_err("The 'instance' attribute is malformed.");
		return error;
	}

	error = jnla_get_u32(attrs[IFEA_NS], "namespace", &entry->ns);
	if (error)
		return error;
	error = jnla_get_u8(attrs[IFEA_XF], "framework", &entry->xf);
	if (error)
		return error;
	return jnla_get_str(attrs[IFEA_INAME], "instance name",
			INAME_MAX_SIZE, entry->iname);
}

static int serialize_instance(struct xlator *entry, void *arg)
{
	struct sk_buff *skb = arg;
	struct nlattr *root;
	int error;

	root = nla_nest_start(skb, LA_ENTRY);
	if (!root)
		return 1;

	error = nla_put_u32(skb, IFEA_NS, ((__u64)entry->ns) & 0xFFFFFFFF);
	if (error)
		goto cancel;
	error = nla_put_u8(skb, IFEA_XF, xlator_flags2xf(entry->flags));
	if (error)
		goto cancel;
	error = nla_put_string(skb, IFEA_INAME, entry->iname);
	if (error)
		goto cancel;

	nla_nest_end(skb, root);
	return 0;

cancel:
	nla_nest_cancel(skb, root);
	return 1;
}

int handle_instance_foreach(struct sk_buff *skb, struct genl_info *info)
{
	struct instance_entry_usr offset, *offset_ptr;
	struct jool_response response;
	int error;

	log_debug("Sending instance table to userspace.");

	error = request_handle_start(info, XT_ANY, NULL);
	if (error)
		goto fail;

	offset_ptr = NULL;
	if (info->attrs[RA_OFFSET]) {
		error = parse_instance(info->attrs[RA_OFFSET], &offset);
		if (error)
			goto revert_start;
		offset_ptr = &offset;
	}

	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	error = xlator_foreach(get_jool_hdr(info)->xt, serialize_instance,
			response.skb, offset_ptr);

	error = jresponse_send_array(&response, error);
	if (error)
		goto revert_start;

	request_handle_end(NULL);
	return 0;

revert_start:
	request_handle_end(NULL);
fail:
	return jresponse_send_simple(info, error);
}

int handle_instance_add(struct sk_buff *skb, struct genl_info *info)
{
	static struct nla_policy add_policy[IARA_COUNT] = {
		[IARA_XF] = { .type = NLA_U8 },
		[IARA_POOL6] = { .type = NLA_NESTED, },
	};
	struct nlattr *attrs[IARA_COUNT];
	struct ipv6_prefix pool6, *pool6_ptr;
	__u8 xf;
	int error;

	log_debug("Adding Jool instance.");

	error = request_handle_start(info, XT_ANY, NULL);
	if (error)
		goto abort;

	if (!info->attrs[RA_OPERAND]) {
		log_err("The request is missing an 'Operand' attribute.");
		error = -EINVAL;
		goto revert_start;
	}

	error = nla_parse_nested(attrs, IARA_MAX, info->attrs[RA_OPERAND], add_policy, NULL);
	if (error) {
		log_err("The 'Operand' attribute is malformed.");
		return error;
	}

	error = jnla_get_u8(attrs[IARA_XF], "framework", &xf);
	if (error)
		goto revert_start;
	pool6_ptr = NULL;
	if (attrs[IARA_POOL6]) {
		error = jnla_get_prefix6(attrs[IARA_POOL6], "pool6", &pool6);
		if (error)
			goto revert_start;
		pool6_ptr = &pool6;
	}

	return jresponse_send_simple(info, xlator_add(
		xf | get_jool_hdr(info)->xt,
		get_jool_hdr(info)->iname,
		pool6_ptr,
		NULL
	));

revert_start:
	request_handle_end(NULL);
abort:
	return jresponse_send_simple(info, error);
}

int handle_instance_hello(struct sk_buff *skb, struct genl_info *info)
{
	struct jool_response response;
	int error;

	log_debug("Handling instance Hello.");

	error = request_handle_start(info, XT_ANY, NULL);
	if (error)
		goto fail;

	error = jresponse_init(&response, info);
	if (error)
		goto revert_start;

	error = xlator_find_current(get_jool_hdr(info)->iname,
			XF_ANY | get_jool_hdr(info)->xt, NULL);
	switch (error) {
	case 0:
		error = nla_put_u8(response.skb, ISRA_STATUS, IHS_ALIVE);
		if (error)
			goto put_failure;
		break;
	case -ESRCH:
		error = nla_put_u8(response.skb, ISRA_STATUS, IHS_DEAD);
		if (error)
			goto put_failure;
		break;
	default:
		log_err("Unknown status.");
		error = -EINVAL;
		goto revert_start;
	}

	return jresponse_send(&response);

put_failure:
	report_put_failure();
revert_start:
	request_handle_end(NULL);
fail:
	return jresponse_send_simple(info, error);
}

int handle_instance_rm(struct sk_buff *skb, struct genl_info *info)
{
	int error;

	log_debug("Removing Jool instance.");

	error = request_handle_start(info, XT_ANY, NULL);
	if (!error)
		error = xlator_rm(get_jool_hdr(info)->xt, get_jool_hdr(info)->iname);
	request_handle_end(NULL);

	return jresponse_send_simple(info, error);
}

int handle_instance_flush(struct sk_buff *skb, struct genl_info *info)
{
	int error;

	log_debug("Flushing all instances from this namespace.");

	error = request_handle_start(info, XT_ANY, NULL);
	if (!error)
		error = xlator_flush(get_jool_hdr(info)->xt);
	request_handle_end(NULL);

	return jresponse_send_simple(info, error);
}
