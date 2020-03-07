#include "usr/nl/instance.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include "usr/nl/attribute.h"

struct foreach_args {
	instance_foreach_cb cb;
	void *args;
	bool done;
	struct instance_entry_usr last;
};

static struct jool_result entry2attr(struct instance_entry_usr *entry,
		int attrtype, struct nl_msg *msg)
{
	struct nlattr *root;

	root = nla_nest_start(msg, attrtype);
	if (!root)
		goto nla_put_failure;

	NLA_PUT_U32(msg, IFEA_NS, entry->ns);
	NLA_PUT_U8(msg, IFEA_XF, entry->xf);
	NLA_PUT_STRING(msg, IFEA_INAME, entry->iname);

	nla_nest_end(msg, root);
	return result_success();

nla_put_failure:
	return packet_too_small();
}

static struct jool_result attr2entry(struct nlattr *root,
		struct instance_entry_usr *entry)
{
	struct nlattr *attrs[IFEA_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, IFEA_MAX, root, instance_entry_policy);
	if (result.error)
		return result;

	entry->ns = nla_get_u32(attrs[IFEA_NS]);
	entry->xf = nla_get_u8(attrs[IFEA_XF]);
	strcpy(entry->iname, nla_get_string(attrs[IFEA_INAME]));
	return result_success();
}

static struct jool_result handle_foreach_response(struct nl_msg *response,
		void *arg)
{
	struct foreach_args *args;
	struct genlmsghdr *ghdr;
	struct joolnl_hdr *jhdr;
	struct nlattr *attr;
	int rem;
	struct instance_entry_usr entry;
	struct jool_result result;

	args = arg;
	ghdr = genlmsg_hdr(nlmsg_hdr(response));

	foreach_entry(attr, ghdr, rem) {
		result = attr2entry(attr, &entry);
		if (result.error)
			return result;

		result = args->cb(&entry, args->args);
		if (result.error)
			return result;

		memcpy(&args->last, &entry, sizeof(entry));
	}

	jhdr = genlmsg_user_hdr(ghdr);
	args->done = !(jhdr->flags & HDRFLAGS_M);
	return result_success();
}

struct jool_result instance_foreach(struct jool_socket *sk,
		instance_foreach_cb cb, void *_args)
{
	struct nl_msg *msg;
	struct foreach_args args;
	struct jool_result result;
	bool first_request;

	args.cb = cb;
	args.args = _args;
	args.done = false;
	memset(&args.last, 0, sizeof(args.last));
	first_request = true;

	do {
		result = allocate_jool_nlmsg(sk, NULL, JOP_INSTANCE_FOREACH, 0, &msg);
		if (result.error)
			return result;

		if (first_request) {
			first_request = false;
		} else {
			result = entry2attr(&args.last, RA_OFFSET, msg);
			if (result.error) {
				nlmsg_free(msg);
				return result;
			}
		}

		result = netlink_request(sk, msg, handle_foreach_response, &args);
		if (result.error)
			return result;
	} while (!args.done);

	return result_success();
}

static struct jool_result jool_hello_cb(struct nl_msg *response, void *status)
{
	static struct nla_policy status_policy[ISRA_COUNT] = {
		[ISRA_STATUS] = { .type = NLA_U8 },
	};
	struct nlattr *attrs[ISRA_COUNT];
	struct jool_result result;

	result = jnla_parse_msg(response, attrs, ISRA_MAX, status_policy, true);
	if (result.error)
		return result;

	*((enum instance_hello_status *)status) = nla_get_u8(attrs[ISRA_STATUS]);
	return result_success();
}

/**
 * If the instance exists, @result will be zero. If the instance does not exist,
 * @result will be 1.
 */
struct jool_result instance_hello(struct jool_socket *sk, char *iname,
		enum instance_hello_status *status)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, JOP_INSTANCE_HELLO, 0, &msg);
	if (result.error)
		return result;

	return netlink_request(sk, msg, jool_hello_cb, status);
}

struct jool_result instance_add(struct jool_socket *sk, xlator_framework xf,
		char *iname, struct ipv6_prefix *pool6)
{
	struct nl_msg *msg;
	struct nlattr *root;
	struct jool_result result;

	result.error = xf_validate(xf);
	if (result.error)
		return result_from_error(result.error, XF_VALIDATE_ERRMSG);

	result = allocate_jool_nlmsg(sk, iname, JOP_INSTANCE_ADD, 0, &msg);
	if (result.error)
		return result;

	root = nla_nest_start(msg, RA_OPERAND);
	if (!root)
		goto nla_put_failure;

	NLA_PUT_U8(msg, IARA_XF, xf);
	if (pool6 && nla_put_prefix6(msg, IARA_POOL6, pool6))
		goto nla_put_failure;

	nla_nest_end(msg, root);
	return netlink_request(sk, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);
	return packet_too_small();
}

struct jool_result instance_rm(struct jool_socket *sk, char *iname)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, JOP_INSTANCE_RM, 0, &msg);
	if (result.error)
		return result;

	return netlink_request(sk, msg, NULL, NULL);
}

struct jool_result instance_flush(struct jool_socket *sk)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, NULL, JOP_INSTANCE_FLUSH, 0, &msg);
	if (result.error)
		return result;

	return netlink_request(sk, msg, NULL, NULL);
}
