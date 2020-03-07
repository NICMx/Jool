#include "blacklist4.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include "usr/nl/attribute.h"

struct foreach_args {
	blacklist4_foreach_cb cb;
	void *args;
	bool done;
	struct ipv4_prefix last;
};

static struct jool_result entry2attr(struct nl_msg *msg, int attrtype, struct ipv4_prefix *entry)
{
	return nla_put_prefix4(msg, attrtype, entry)
			? packet_too_small()
			: result_success();
}

static struct jool_result attr2entry(struct nlattr *attr,
		struct ipv4_prefix *entry)
{
	if (nla_type(attr) != LA_ENTRY)
		return result_success(); /* dunno; skip I guess */
	return nla_get_prefix4(attr, entry);
}

static struct jool_result handle_foreach_response(struct nl_msg *response,
		void *arg)
{
	struct foreach_args *args;
	struct genlmsghdr *ghdr;
	struct joolnl_hdr *jhdr;
	struct nlattr *attr;
	int rem;
	struct ipv4_prefix entry;
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

struct jool_result blacklist4_foreach(struct jool_socket *sk, char *iname,
		blacklist4_foreach_cb cb, void *_args)
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
		result = allocate_jool_nlmsg(sk, iname, JOP_BL4_FOREACH, 0, &msg);
		if (result.error)
			return result;

		if (first_request) {
			first_request = false;
		} else {
			result = entry2attr(msg, RA_OFFSET, &args.last);
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

static struct jool_result __update(struct jool_socket *sk, char *iname,
		enum jool_operation operation, struct ipv4_prefix *prefix,
		__u8 force)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, operation, force, &msg);
	if (result.error)
		return result;

	if (prefix) {
		result = entry2attr(msg, RA_OPERAND, prefix);
		if (result.error) {
			nlmsg_free(msg);
			return result;
		}
	}

	return netlink_request(sk, msg, NULL, NULL);
}

struct jool_result blacklist4_add(struct jool_socket *sk, char *iname,
		struct ipv4_prefix *prefix, bool force)
{
	return __update(sk, iname, JOP_BL4_ADD, prefix, force ? HDRFLAGS_FORCE : 0);
}

struct jool_result blacklist4_rm(struct jool_socket *sk, char *iname,
		struct ipv4_prefix *prefix)
{
	return __update(sk, iname, JOP_BL4_RM, prefix, 0);
}

struct jool_result blacklist4_flush(struct jool_socket *sk, char *iname)
{
	return __update(sk, iname, JOP_BL4_FLUSH, NULL, 0);
}
