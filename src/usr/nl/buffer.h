#ifndef SRC_USR_NL_BUFFER_H_
#define SRC_USR_NL_BUFFER_H_

#include <stddef.h> /* size_t */

#include "jool_socket.h"

struct nl_buffer;

struct nl_buffer *nlbuffer_alloc(struct jool_socket *sk, char *iname);
void nlbuffer_destroy(struct nl_buffer *buffer);

struct jool_result nlbuffer_write(struct nl_buffer *buffer,
		void *payload, size_t payload_len);
struct jool_result nlbuffer_flush(struct nl_buffer *buffer);

#endif /* SRC_USR_NL_BUFFER_H_ */
