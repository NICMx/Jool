#include "usr/nl/p4block.h"

#include <errno.h>
#include <netlink/genl/genl.h>
#include "usr/nl/attribute.h"
#include "usr/nl/common.h"

struct jool_result joolnl_p4block_foreach(struct joolnl_socket *sk,
		char const *iname)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, JNLOP_P4BLOCK_FOREACH, 0, &msg);
	if (result.error)
		return result;

	return joolnl_request(sk, msg, NULL, NULL);
}

static struct jool_result __update(struct joolnl_socket *sk, char const *iname,
		enum joolnl_operation operation, struct p4block const *blk)
{
	struct nl_msg *msg;
	struct jool_result result;

	result = joolnl_alloc_msg(sk, iname, operation, 0, &msg);
	if (result.error)
		return result;

	if (nla_put_p4block(msg, JNLAR_OPERAND, blk) < 0) {
		nlmsg_free(msg);
		return joolnl_err_msgsize();
	}

	return joolnl_request(sk, msg, NULL, NULL);
}

struct jool_result joolnl_p4block_add(struct joolnl_socket *sk,
		char const *iname, struct p4block const *blk)
{
	return __update(sk, iname, JNLOP_P4BLOCK_ADD, blk);
}

struct jool_result joolnl_p4block_rm(struct joolnl_socket *sk,
		char const *iname, struct p4block const *blk)
{
	return __update(sk, iname, JNLOP_P4BLOCK_RM, blk);
}
