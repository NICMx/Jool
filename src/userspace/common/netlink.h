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
	struct response_hdr *hdr;
	void *payload;
	size_t payload_len;
};

int jnl_init_socket(struct jnl_socket *socket);
void jnl_destroy_socket(struct jnl_socket *socket);

typedef int (*jnl_response_cb)(struct jnl_response *, void *);

int jnl_request(struct jnl_socket *socket, char *instance,
		enum config_mode mode, enum config_operation op,
		void *data, int data_len,
		jnl_response_cb cb, void *cb_arg);
int jnl_single_request(char *instance,
		enum config_mode mode, enum config_operation op,
		void *data, int data_len,
		jnl_response_cb cb, void *cb_arg);

#define JNL_SIMPLE_REQUEST(instance, mode, op, request) \
	jnl_single_request(instance, mode, op, &request, sizeof(request), NULL, NULL)
#define JNL_HDR_REQUEST(instance, mode, op) \
	jnl_single_request(instance, mode, op, NULL, 0, NULL, NULL)

/* TODO ? */
int netlink_print_error(int error);
int netlink_parse_response(void *data, size_t data_len,
		struct jnl_response *result);

#endif /* _JOOL_USR_NETLINK_H_ */
