#include "nat64/mod/common/nl_buffer.h"
#include <net/netlink.h>
#include "nat64/mod/common/types.h"


static int flush(struct nl_buffer *buffer, __u16 nlmsg_type, __u16	nlmsg_flags)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nl_hdr_out;
	int res;

	skb_out = nlmsg_new(NLMSG_ALIGN(buffer->len), GFP_ATOMIC);
	if (!skb_out) {
		log_err("Failed to allocate a response skb to the user.");
		return -ENOMEM;
	}

	nl_hdr_out = nlmsg_put(skb_out,
			0, /* src_pid (0 = kernel) */
			buffer->request_hdr->nlmsg_seq, /* seq */
			nlmsg_type, /* type */
			buffer->len, /* payload len */
			nlmsg_flags); /* flags. */
	memcpy(nlmsg_data(nl_hdr_out), buffer->bytes, buffer->len);
	/* NETLINK_CB(skb_out).dst_group = 0; */

	res = nlmsg_unicast(buffer->socket, skb_out, buffer->request_hdr->nlmsg_pid);
	if (res < 0) {
		log_err("Error code %d while returning response to the user.", res);
		return res;
	}

	buffer->len = 0;

	return 0;
}

struct nl_buffer *nlbuffer_create(struct sock *nl_socket, struct nlmsghdr *nl_hdr)
{
	struct nl_buffer *result;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result) {
		log_err("Could not allocate an output buffer to userspace.");
		return NULL;
	}

	result->socket = nl_socket;
	result->request_hdr = nl_hdr;
	result->len = 0;

	return result;
}

int nlbuffer_write(struct nl_buffer *stream, void *payload, int payload_len)
{
	if (payload == NULL || payload_len == 0)
		return 0;

	if (payload_len > NLBUFFER_SIZE) {
		/* This will never happen in this project, so fail blatantly :p. */
		log_err("The data is too big to be streamed. Failing...");
		return -EINVAL;
	}

	if (stream->len + payload_len > NLBUFFER_SIZE) {
		/*
		 * Caller must flush and try again.
		 * Why don't we do that ourselves? the flush might be expensive, so the caller should let
		 * go of any spinlocks.
		 */
		return 1;
	}

	memcpy(stream->bytes + stream->len, payload, payload_len);
	stream->len += payload_len;

	return 0;
}

int nlbuffer_close(struct nl_buffer *stream, bool multi)
{
	return flush(stream, NLMSG_DONE, multi ? NLM_F_MULTI : 0);
}
