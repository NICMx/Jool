#include "nat64/mod/out_stream.h"
#include "net/netlink.h"
#include "nat64/comm/types.h"


static int flush(struct out_stream *stream, __u16 nlmsg_type, __u16	nlmsg_flags)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_hdr_out;
	int res;

	skb_out = nlmsg_new(NLMSG_ALIGN(stream->buffer_len), GFP_ATOMIC);
	if (!skb_out) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a response skb to the user.");
		return -ENOMEM;
	}

	nl_hdr_out = nlmsg_put(skb_out,
			0, /* src_pid (0 = kernel) */
			stream->request_hdr->nlmsg_seq, /* seq */
			nlmsg_type, /* type */
			stream->buffer_len, /* payload len */
			nlmsg_flags); /* flags. */
	memcpy(nlmsg_data(nl_hdr_out), stream->buffer, stream->buffer_len);
	/* NETLINK_CB(skb_out).dst_group = 0; */

	res = nlmsg_unicast(stream->socket, skb_out, stream->request_hdr->nlmsg_pid);
	if (res < 0) {
		log_err(ERR_NETLINK, "Error code %d while returning response to the user.", res);
		return res;
	}

	stream->buffer_len = 0;

	return 0;
}

void stream_init(struct out_stream *stream, struct sock *nl_socket, struct nlmsghdr *nl_hdr)
{
	stream->socket = nl_socket;
	stream->request_hdr = nl_hdr;
	stream->buffer_len = 0;
}

int stream_write(struct out_stream *stream, void *payload, int payload_len)
{
	if (payload == NULL || payload_len == 0)
		return 0;

	/*
	 * TODO (fine) if payload_len > BUFFER_SIZE, this will go downhill.
	 * Will never happen in this project, hence the low priority.
	 */
	if (stream->buffer_len + payload_len > OUT_STREAM_BUFFER_SIZE) {
		return 1;
	}

	memcpy(stream->buffer + stream->buffer_len, payload, payload_len);
	stream->buffer_len += payload_len;
	/* There might still be room in the buffer, so don't flush it yet. */

	return 0;
}

int stream_close(struct out_stream *stream)
{
	return flush(stream, NLMSG_DONE, 0);
}

int stream_close_continue(struct out_stream *stream)
{
	return flush(stream, NLMSG_DONE, NLM_F_MULTI);
}
