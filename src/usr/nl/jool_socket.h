#ifndef SRC_USR_NL_JOOL_SOCKET_H_
#define SRC_USR_NL_JOOL_SOCKET_H_

#include <netlink/netlink.h>
#include "usr/util/result.h"

struct jool_socket {
	struct nl_sock *sk;
	int family;
};

struct jool_response {
	struct response_hdr *hdr;
	void *payload;
	size_t payload_len;
};

struct jool_result netlink_setup(struct jool_socket *socket);
void netlink_teardown(struct jool_socket *socket);

typedef struct jool_result (*jool_response_cb)(struct jool_response *, void *);

/* _send only sends a message. _request both sends and handles the response. */
struct jool_result netlink_send(struct jool_socket *socket, char *iname,
		void *request, __u32 request_len);
struct jool_result netlink_request(struct jool_socket *socket, char *iname,
		void *request, __u32 request_len,
		jool_response_cb cb, void *cb_arg);

struct jool_result netlink_parse_response(void *data, size_t data_len,
		struct jool_response *response);

#endif /* SRC_USR_NL_JOOL_SOCKET_H_ */
