#ifndef SRC_USR_NL_BLACKLIST_H_
#define SRC_USR_NL_BLACKLIST_H_

#include "common/types.h"
#include "jool_socket.h"

typedef struct jool_result (*blacklist4_foreach_cb)(struct ipv4_prefix *entry,
		void *args);

struct jool_result blacklist4_foreach(struct jool_socket *sk, char *iname,
		blacklist4_foreach_cb cb, void *_args);
struct jool_result blacklist4_add(struct jool_socket *sk, char *iname,
		struct ipv4_prefix *addrs, bool force);
struct jool_result blacklist4_rm(struct jool_socket *sk, char *iname,
		struct ipv4_prefix *addrs);
struct jool_result blacklist4_flush(struct jool_socket *sk, char *iname);

#endif /* SRC_USR_NL_BLACKLIST_H_ */
