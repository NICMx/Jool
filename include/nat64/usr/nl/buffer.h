#ifndef _JOOL_USR_NL_BUFFER_H
#define _JOOL_USR_NL_BUFFER_H

#include <stdio.h>

struct nl_buffer;

struct nl_buffer *nlbuffer_create(void);
void nlbuffer_destroy(struct nl_buffer *buffer);

int nlbuffer_write(struct nl_buffer *buffer, void *payload, size_t payload_len);
int nlbuffer_flush(struct nl_buffer *buffer);

#endif /* _JOOL_USR_NL_BUFFER_H */
