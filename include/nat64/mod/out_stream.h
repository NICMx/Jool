#ifndef _NF_NAT64_STREAM_H
#define _NF_NAT64_STREAM_H

#include "linux/netlink.h"

#define OUT_STREAM_BUFFER_SIZE NLMSG_DEFAULT_SIZE


struct out_stream {
	struct sock *socket;
	struct nlmsghdr *request_hdr;

	unsigned char buffer[OUT_STREAM_BUFFER_SIZE];
	int buffer_len;
};

void stream_init(struct out_stream *stream, struct sock *nl_socket, struct nlmsghdr *nl_hdr);
int stream_write(struct out_stream *stream, void *payload, int payload_len);
void stream_close(struct out_stream *stream);

#endif /* _NF_NAT64_STREAM_H */
