#include "buffer.h"

#include <errno.h>
#include "common/config.h"

#define BUFFER_MAX 256

struct nl_buffer {
	struct jool_socket *sk;
	char iname[INAME_MAX_LEN];
	unsigned char chars[BUFFER_MAX];
	size_t len;
};

struct nl_buffer *nlbuffer_alloc(struct jool_socket *sk, char *iname)
{
	struct nl_buffer *buffer;

	buffer = malloc(sizeof(struct nl_buffer));
	if (!buffer)
		return NULL;

	buffer->sk = sk;
	strcpy(buffer->iname, iname);
	buffer->len = 0;

	return buffer;
}

void nlbuffer_destroy(struct nl_buffer *buffer)
{
	free(buffer);
}

struct jool_result nlbuffer_write(struct nl_buffer *buffer,
		void *payload, size_t payload_len)
{
	if (payload_len > BUFFER_MAX) {
		return result_from_error(
			-EINVAL,
			"Packet content is larger than packet limit."
		);
	}

	if (buffer->len + payload_len > BUFFER_MAX) {
		return result_from_error(
			-ENOSPC,
			"Message does not fit in the packet."
		);
	}

	memcpy(buffer->chars + buffer->len, payload, payload_len);
	buffer->len += payload_len;
	return result_success();
}

struct jool_result nlbuffer_flush(struct nl_buffer *buffer)
{
	struct jool_result result;

	result = netlink_request(buffer->sk, buffer->iname,
			&buffer->chars[0], buffer->len,
			NULL, NULL);
	buffer->len = 0;

	return result;
}
