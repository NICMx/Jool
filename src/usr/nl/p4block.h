#ifndef SRC_USR_NL_P4BLOCK_H_
#define SRC_USR_NL_P4BLOCK_H_

#include "common/config.h"
#include "usr/nl/core.h"

struct jool_result joolnl_p4block_foreach(
	struct joolnl_socket *sk,
	char const *iname
);

struct jool_result joolnl_p4block_add(
	struct joolnl_socket *sk,
	char const *iname,
	struct p4block const *blk
);

struct jool_result joolnl_p4block_rm(
	struct joolnl_socket *sk,
	char const *iname,
	struct p4block const *blk
);

#endif /* SRC_USR_NL_P4BLOCK_H_ */
