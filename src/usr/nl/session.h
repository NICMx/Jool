#ifndef SRC_USR_NL_SESSION_H_
#define SRC_USR_NL_SESSION_H_

#include "common/config.h"
#include "usr/nl/core.h"

typedef struct jool_result (*session_foreach_cb)(
	struct session_entry_usr const *entry, void *args
);

struct jool_result joolnl_session_foreach(
	struct joolnl_socket *sk,
	char const *iname,
	l4_protocol proto,
	session_foreach_cb cb,
	void *args
);

#endif /* SRC_USR_NL_SESSION_H_ */
