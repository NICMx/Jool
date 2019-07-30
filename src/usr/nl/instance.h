#ifndef SRC_USR_NL_INSTANCE_H_
#define SRC_USR_NL_INSTANCE_H_

#include "common/config.h"
#include "jool_socket.h"

typedef struct jool_result (*instance_foreach_entry)(
		struct instance_entry_usr *instance, void *arg);

struct jool_result instance_foreach(struct jool_socket *sk,
		instance_foreach_entry cb, void *args);
struct jool_result instance_hello(struct jool_socket *sk, char *iname,
		enum instance_hello_status *status);
struct jool_result instance_add(struct jool_socket *sk, jframework fw,
		char *iname, struct ipv6_prefix *pool6);
struct jool_result instance_rm(struct jool_socket *sk, char *iname);
struct jool_result instance_flush(struct jool_socket *sk);

#endif /* SRC_USR_NL_INSTANCE_H_ */
