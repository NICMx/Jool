#include "usr/nl/eamt.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include "usr/nl/attribute.h"

struct foreach_args {
	eamt_foreach_cb cb;
	void *args;
	bool done;
	struct eamt_entry last;
};

static struct jool_result entry2attr(struct eamt_entry *entry,
		struct nl_msg *msg)
{
	struct nlattr *root;

	root = nla_nest_start(msg, RA_EAMT_ENTRY);
	if (!root)
		goto nla_put_failure;

	if (nla_put_prefix6(msg, EA_PREFIX6, &entry->prefix6))
		goto nla_put_failure;
	if (nla_put_prefix4(msg, EA_PREFIX4, &entry->prefix4))
		goto nla_put_failure;

	nla_nest_end(msg, root);
	return result_success();

nla_put_failure:
	return packet_too_small();
}

static struct jool_result attr2entry(struct nlattr *attr,
		struct eamt_entry *entry)
{
	struct nlattr *eam_attrs[EA_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(eam_attrs, EA_MAX, attr, eam_policy);
	if (result.error)
		return result;

	result = nla_get_prefix6(eam_attrs[EA_PREFIX6], &entry->prefix6);
	if (result.error)
		return result;

	return nla_get_prefix4(eam_attrs[EA_PREFIX4], &entry->prefix4);
}

static struct jool_result handle_foreach_response(struct nl_msg *response,
		void *arg)
{
	struct foreach_args *args;
	struct genlmsghdr *ghdr;
	struct request_hdr *jhdr;
	struct nlattr *attr;
	int rem;
	struct eamt_entry entry;
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

struct jool_result eamt_foreach(struct jool_socket *sk, char *iname,
		eamt_foreach_cb cb, void *_args)
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
		result = allocate_jool_nlmsg(sk, iname, JOP_EAMT_FOREACH, 0, &msg);
		if (result.error)
			return result;

		if (first_request) {
			first_request = false;
		} else {
			result = entry2attr(&args.last, msg);
			if (result.error)
				return result;
		}

		result = netlink_request(sk, msg, handle_foreach_response, &args);
		if (result.error)
			return result;
	} while (!args.done);

	return result_success();
}

static struct jool_result __update(struct jool_socket *sk, char *iname,
		enum jool_operation operation,
		struct ipv6_prefix *p6, struct ipv4_prefix *p4,
		__u8 flags)
{
	struct nl_msg *msg;
	struct nlattr *root;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, operation, flags, &msg);
	if (result.error)
		return result;

	root = nla_nest_start(msg, RA_EAMT_ENTRY);
	if (!root)
		goto nla_put_failure;

	if (p6 && nla_put_prefix6(msg, EA_PREFIX6, p6))
		goto nla_put_failure;
	if (p4 && nla_put_prefix4(msg, EA_PREFIX4, p4))
		goto nla_put_failure;

	nla_nest_end(msg, root);
	return netlink_request(sk, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);
	return packet_too_small();
}

struct jool_result eamt_add(struct jool_socket *sk, char *iname,
		struct ipv6_prefix *p6, struct ipv4_prefix *p4, bool force)
{
	return __update(sk, iname, JOP_EAMT_ADD, p6, p4, force ? HDRFLAGS_FORCE : 0);
}

struct jool_result eamt_rm(struct jool_socket *sk, char *iname,
		struct ipv6_prefix *p6, struct ipv4_prefix *p4)
{
	return __update(sk, iname, JOP_EAMT_RM, p6, p4, 0);
}

struct jool_result eamt_flush(struct jool_socket *sk, char *iname)
{
	return __update(sk, iname, JOP_EAMT_FLUSH, NULL, NULL, 0);
}
