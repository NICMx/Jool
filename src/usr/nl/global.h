#ifndef SRC_USR_NL_GLOBAL_H_
#define SRC_USR_NL_GLOBAL_H_

#include "common/globals.h"
#include "usr/nl/core.h"

struct jool_result joolnl_global_query(
	struct joolnl_socket *sk,
	char const *iname,
	struct globals *out
);

struct jool_result joolnl_global_update(
	struct joolnl_socket *sk,
	char const *iname,
	struct global_field const *field,
	char const *value,
	bool force
);

#endif /* SRC_USR_NL_GLOBAL_H_ */
