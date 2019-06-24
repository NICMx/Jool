#ifndef SRC_USR_NL_SESSION_H_
#define SRC_USR_NL_SESSION_H_

#include "common/config.h"
#include "jool_socket.h"

typedef struct jool_result (*session_foreach_cb)(
		struct session_entry_usr *entry, void *args);

struct jool_result session_foreach(struct jool_socket *sk, char *iname,
		l4_protocol proto, session_foreach_cb cb, void *args);

#endif /* SRC_USR_NL_SESSION_H_ */
