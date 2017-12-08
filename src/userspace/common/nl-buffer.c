#include "nat64/usr/nl/buffer.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "nat64/common/config.h"
#include "nat64/common/types.h"
#include "nat64/usr/netlink.h"

#define BUFFER_MAX 256

struct nl_buffer {
	unsigned char chars[BUFFER_MAX];
	size_t len;
};

struct nl_buffer *nlbuffer_create(void)
{
	struct nl_buffer *buffer;

	buffer = malloc(sizeof(*buffer));
	if (!buffer)
		return NULL;

	buffer->len = 0;

	return buffer;
}

void nlbuffer_destroy(struct nl_buffer *buffer)
{
	free(buffer);
}

int nlbuffer_write(struct nl_buffer *buffer, void *payload, size_t payload_len)
{
	if (payload_len > BUFFER_MAX) {
		log_err("Packet content is larger than packet limit.");
		return -EINVAL;
	}

	if (buffer->len + payload_len > BUFFER_MAX)
		return -ENOSPC;

	memcpy(buffer->chars + buffer->len, payload, payload_len);
	buffer->len += payload_len;
	return 0;
}

int nlbuffer_flush(struct nl_buffer *buffer)
{
	int error;

	error = netlink_request(&buffer->chars[0], buffer->len, NULL, NULL);
	buffer->len = 0;

	return error;
}
