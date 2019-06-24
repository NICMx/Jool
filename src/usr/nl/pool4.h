#ifndef SRC_USR_NL_POOL4_H_
#define SRC_USR_NL_POOL4_H_

#include "common/config.h"
#include "jool_socket.h"

typedef struct jool_result (*pool4_foreach_cb)(struct pool4_sample *sample,
		void *args);

struct jool_result pool4_foreach(struct jool_socket *sk, char *iname,
		l4_protocol proto, pool4_foreach_cb cb, void *args);
struct jool_result pool4_add(struct jool_socket *sk, char *iname,
		struct pool4_entry_usr *entry);
struct jool_result pool4_rm(struct jool_socket *sk, char *iname,
		struct pool4_entry_usr *entry, bool quick);
struct jool_result pool4_flush(struct jool_socket *sk, char *iname, bool quick);

#endif /* SRC_USR_NL_POOL4_H_ */
