#ifndef _JOOL_USR_NETLINK2_H_
#define _JOOL_USR_NETLINK2_H_

#include <netlink/netlink.h>


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

struct jool_response {
	struct response_hdr *hdr;
	void *payload;
	size_t payload_len;
};

typedef int (*jool_response_cb)(struct jool_response *, void *);
int netlink_request(void *request, __u32 request_len,
		jool_response_cb cb, void *cb_arg);
int netlink_request_simple(void *request, __u32 request_len);

int netlink_init(void);
void netlink_destroy(void);

int netlink_print_error(int error);

int netlink_parse_response(void *data, size_t data_len,
		struct jool_response *result);

#endif /* _JOOL_USR_NETLINK_H_ */
