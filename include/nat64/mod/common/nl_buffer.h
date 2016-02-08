#ifndef _JOOL_MOD_NL_BUFFER_H
#define _JOOL_MOD_NL_BUFFER_H

/**
 * @file
 * A dumb buffer that somewhat behaves like a stream (because of the write function).
 * The buffer will eventually become a single Netlink message, so it's not circular and cannot be
 * resized or anything.
 *
 * Specifically intended for the config module's convenience.
 */

#include "linux/netlink.h"

#define NLBUFFER_SIZE NLMSG_DEFAULT_SIZE

struct nl_buffer {
	struct sock *socket;
	struct nlmsghdr *request_hdr;

	unsigned char bytes[NLBUFFER_SIZE];
	int len;
};

/**
 * Allocates a buffer and readies it so data can be written in it.
 */
struct nl_buffer *nlbuffer_create(struct sock *nl_socket, struct nlmsghdr *nl_hdr);
/**
 * Writes "len" bytes from "data" into "buffer". Watch out for the return values.
 *
 * @return 0 on success. 1 on non-fatal trouble; flush and try again. Negative on fatal trouble.
 *
 * By "flush and try again" I mean "stop writing and call nlbuffer_close_continue()" :p.
 */
int nlbuffer_write(struct nl_buffer *buffer, void *data, int len);
/**
 * Turns "buffer" into a Netlink message and sends it to userspace.
 * If multi is nonzero, the userspace app will be notified that there's remaining data that didn't
 * fit into buffer->bytes, so it should request it somehow.
 */
int nlbuffer_close(struct nl_buffer *buffer, bool multi);

#endif /* _JOOL_MOD_OUT_STREAM_H */
