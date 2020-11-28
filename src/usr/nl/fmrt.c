#include "usr/nl/fmrt.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include "usr/nl/attribute.h"
#include "usr/nl/common.h"

struct foreach_args {
	joolnl_fmrt_foreach_cb cb;
	void *args;
	bool done;
	struct ipv4_prefix last;
};

static struct jool_result handle_foreach_response(struct nl_msg *response,
		void *arg)
{
	struct foreach_args *args = arg;
	struct nlattr *attr;
	int rem;
	struct mapping_rule fmr;
	struct jool_result result;

	result = joolnl_init_foreach_list(response, "fmr", &args->done);
	if (result.error)
		return result;

	foreach_entry(attr, genlmsg_hdr(nlmsg_hdr(response)), rem) {
		result = nla_get_fmr(attr, &fmr);
		if (result.error)
			return result;

		result = args->cb(&fmr, args->args);
		if (result.error)
			return result;

		args->last = fmr.prefix4;
	}

	return result_success();
}

struct jool_result joolnl_fmrt_foreach(struct joolnl_socket *sk,
		char const *iname, joolnl_fmrt_foreach_cb cb, void *_args)
{
	struct nl_msg *msg;
	struct foreach_args args;
	struct jool_result result;
	bool first_request;

	args.cb = cb;
	args.args = _args;
	args.done = true;
	memset(&args.last, 0, sizeof(args.last));
	first_request = true;

	do {
		result = joolnl_alloc_msg(sk, iname, JNLOP_FMRT_FOREACH, 0, &msg);
		if (result.error)
			return result;

		if (first_request) {
			first_request = false;

		} else if (nla_put_prefix4(msg, JNLAR_OFFSET, &args.last) < 0) {
			nlmsg_free(msg);
			return joolnl_err_msgsize();
		}

		result = joolnl_request(sk, msg, handle_foreach_response, &args);
		if (result.error)
			return result;
	} while (!args.done);

	return result_success();
}

static struct jool_result __update(struct joolnl_socket *sk, char const *iname,
		enum joolnl_operation operation,
		struct mapping_rule const *rule)
{
	struct nl_msg *msg;
	struct nlattr *root;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, operation, 0, &msg);
	if (result.error)
		return result;

	root = jnla_nest_start(msg, JNLAR_OPERAND);
	if (!root)
		goto nla_put_failure;

	if (nla_put_prefix6(msg, JNLAF_PREFIX6, &rule->prefix6) < 0)
		goto nla_put_failure;
	if (nla_put_prefix4(msg, JNLAF_PREFIX4, &rule->prefix4) < 0)
		goto nla_put_failure;
	if (nla_put_u8(msg, JNLAF_EA_BITS_LENGTH, rule->ea_bits_length) < 0)
		goto nla_put_failure;
	if (nla_put_u8(msg, JNLAF_a, rule->a) < 0)
		goto nla_put_failure;

	nla_nest_end(msg, root);
	return joolnl_request(sk, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);
	return joolnl_err_msgsize();
}

struct jool_result joolnl_fmrt_add(struct joolnl_socket *sk, char const *iname,
		struct mapping_rule const *rule)
{
	return __update(sk, iname, JNLOP_FMRT_ADD, rule);
}

struct jool_result joolnl_fmrt_flush(struct joolnl_socket *sk, char const *iname)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JNLOP_FMRT_FLUSH, 0, &msg);
	if (result.error)
		return result;

	return joolnl_request(sk, msg, NULL, NULL);
}
