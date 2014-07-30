#ifndef _JOOL_MOD_NL_BUFFER_H
#define _JOOL_MOD_NL_BUFFER_H

/**
 * @file
 * A dumb buffer that somewhat behaves like a stream (because of the write function).
 * The buffer will eventually become a single Netlink message, so it's not circular and cannot be
 * resized or anything.
 *
 * Specifically intended for the config module's convenience.
 *
 * @author Alberto Leiva
 * @author Daniel Hernandez
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
 * Readies "buffer" so data can be written in it.
 */
void nlbuffer_init(struct nl_buffer *buffer, struct sock *nl_socket, struct nlmsghdr *nl_hdr);
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
 * Implies that you don't have more information to send to userspace.
 */
int nlbuffer_close(struct nl_buffer *buffer);
/**
 * Turns "buffer" into a Netlink message and sends it to userspace.
 * The userspace app will be notified that there's remaining data that didn't fit into this
 * Netlink message, so it should request it somehow.
 */
int nlbuffer_close_continue(struct nl_buffer *buffer);

#endif /* _JOOL_MOD_OUT_STREAM_H */
