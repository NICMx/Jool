#ifndef _JOOL_USR_NETLINK2_H_
#define _JOOL_USR_NETLINK2_H_

#include <netlink/netlink.h>
#include "nl-protocol.h"

/*
 * Assert we're compiling with libnl version >= 3.0
 *
 * Note: it looks like this shouldn't be here, since it's the configure script's
 * responsibility.
 * However, the configure script seems to fail to detect this properly on RedHat
 * (and maybe others).
 */
#if !defined(LIBNL_VER_NUM)
	#error "Missing LIBNL dependency (need at least version 3)."
#endif
#if LIBNL_VER_NUM < LIBNL_VER(3, 0)
	#error "Unsupported LIBNL library version number (< 3.0)."
#endif

struct jnl_socket {
	struct nl_sock *sk;
	int family;
};

struct jnl_response {
	void *payload;
	size_t payload_len;
};

int jnl_init_socket(struct jnl_socket *socket);
void jnl_destroy_socket(struct jnl_socket *socket);

int jnl_request(struct jnl_socket *socket, struct nl_msg *request,
		nl_recvmsg_msg_cb_t cb, void *cb_arg);
int jnl_single_request(struct nl_msg *request);

int jnl_create_request(char *instance, jool_genl_cmd cmd, struct nl_msg **result);

/* TODO ? */
int netlink_print_error(int error);

#endif /* _JOOL_USR_NETLINK_H_ */
