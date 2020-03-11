#ifndef SRC_USR_NL_JOOL_SOCKET_H_
#define SRC_USR_NL_JOOL_SOCKET_H_

#include <netlink/netlink.h>
#include "common/config.h"
#include "usr/util/result.h"

struct jool_socket {
	struct nl_sock *sk;
	xlator_type xt;
	int genl_family;
};

struct jool_result netlink_setup(struct jool_socket *socket, xlator_type xt);
void netlink_teardown(struct jool_socket *socket);

struct jool_result joolnl_msg2result(struct nl_msg *response);

typedef struct jool_result (*jool_response_cb)(struct nl_msg *, void *);

struct jool_result allocate_jool_nlmsg(struct jool_socket *socket,
		char const *iname, enum jool_operation op, __u8 flags,
		struct nl_msg **out);

struct jool_result netlink_request(struct jool_socket *socket,
		struct nl_msg *msg, jool_response_cb cb, void *cb_arg);

#endif /* SRC_USR_NL_JOOL_SOCKET_H_ */
