#include "usr/nl/pool4.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include "usr/nl/attribute.h"

struct foreach_args {
	pool4_foreach_cb cb;
	void *args;
	bool done;
	struct pool4_entry last;
};

static struct jool_result entry2attr(struct pool4_entry *entry,
		struct nl_msg *msg)
{
	struct nlattr *root;

	root = nla_nest_start(msg, RA_POOL4_ENTRY);
	if (!root)
		goto nla_put_failure;

	NLA_PUT_U32(msg, P4A_MARK, entry->mark);
	NLA_PUT_U32(msg, P4A_ITERATIONS, entry->iterations);
	NLA_PUT_U8(msg, P4A_FLAGS, entry->flags);
	NLA_PUT_U8(msg, P4A_PROTO, entry->proto);
	if (nla_put_prefix4(msg, P4A_PREFIX, &entry->range.prefix))
		goto nla_put_failure;
	NLA_PUT_U16(msg, P4A_PORT_MIN, entry->range.ports.min);
	NLA_PUT_U16(msg, P4A_PORT_MAX, entry->range.ports.max);

	nla_nest_end(msg, root);
	return result_success();

nla_put_failure:
	return packet_too_small();
}

static struct jool_result attr2entry(struct nlattr *attr,
		struct pool4_entry *entry)
{
	struct nlattr *attrs[P4A_COUNT];
	struct jool_result result;

	result = jnla_parse_nested(attrs, P4A_MAX, attr, pool4_entry_policy);
	if (result.error)
		return result;

	entry->mark = nla_get_u32(attrs[P4A_MARK]);
	entry->iterations = nla_get_u32(attrs[P4A_ITERATIONS]);
	entry->flags = nla_get_u8(attrs[P4A_FLAGS]);
	entry->proto = nla_get_u8(attrs[P4A_PROTO]);
	entry->range.ports.min = nla_get_u16(attrs[P4A_PORT_MIN]);
	entry->range.ports.max = nla_get_u16(attrs[P4A_PORT_MAX]);
	return nla_get_prefix4(attrs[P4A_PREFIX], &entry->range.prefix);
}

static struct jool_result handle_foreach_response(struct nl_msg *response,
		void *arg)
{
	struct foreach_args *args;
	struct genlmsghdr *ghdr;
	struct request_hdr *jhdr;
	struct nlattr *attr;
	int rem;
	struct pool4_entry entry;
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

struct jool_result pool4_foreach(struct jool_socket *sk, char *iname,
		l4_protocol proto, pool4_foreach_cb cb, void *_args)
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
		result = allocate_jool_nlmsg(sk, iname, JOP_POOL4_FOREACH, 0, &msg);
		if (result.error)
			return result;

		if (first_request) {
			if (nla_put_u8(msg, RA_PROTO, proto))
				return packet_too_small();
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

static struct jool_result __update(struct jool_socket *sk, char const *iname,
		enum jool_operation operation, struct pool4_entry *entry,
		bool quick)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = allocate_jool_nlmsg(sk, iname, operation, quick ? HDRFLAGS_QUICK : 0, &msg);
	if (result.error)
		return result;

	if (entry) {
		result = entry2attr(entry, msg);
		if (result.error) {
			nlmsg_free(msg);
			return result;
		}
	}

	return netlink_request(sk, msg, NULL, NULL);
}

struct jool_result pool4_add(struct jool_socket *sk, char *iname,
		struct pool4_entry *entry)
{
	return __update(sk, iname, JOP_POOL4_ADD, entry, false);
}

struct jool_result pool4_rm(struct jool_socket *sk, char *iname,
		struct pool4_entry *entry, bool quick)
{
	return __update(sk, iname, JOP_POOL4_RM, entry, quick);
}

struct jool_result pool4_flush(struct jool_socket *sk, char *iname, bool quick)
{
	return __update(sk, iname, JOP_POOL4_FLUSH, NULL, quick);
}
