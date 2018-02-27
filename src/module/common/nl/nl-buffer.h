#ifndef SRC_MODULE_COMMON_NL_NL_BUFFER_H_
#define SRC_MODULE_COMMON_NL_NL_BUFFER_H_

#include "nl-protocol.h"

/**
 * Caller writes on the buffer. Once the buffer is full or the caller finishes
 * writing, the buffer is flushed into a Netlink attribute and the resulting
 * skb is fetched to the client.
 *
 * If the buffer was full, the client is expected to request the remaining
 * information later. As of now, the only situation where the buffer can
 * possibly run out of space is when we're sending a database with an
 * undetermined size to userspace - such as the BIB. In other words, we send
 * unfragmented BIB entries in batches. We choose to wait until userspace
 * requests the next batch instead of sending the entire database at once
 * because a) sending too many Netlink packets saturates the kernel (some
 * packets get dropped) and b) it's as good a reason as any to keep releasing
 * the BIB spinlock every now and then during the foreach.
 *
 * Since jnl_buffer uses a data array, why don't we use the skb data array
 * directly as buffer? Because
 *
 * a) nla_put() reserves skb room for the attribute and writes the data content
 *    in one fell swoop. There is no way to do these two steps separately
 *    without direct attribute surgery, and the Netlink API also does not export
 *    a means to access the written data chunk later.
 *    Now, doing this pointer arithmetic surgery wouldn't be difficult, but not
 *    using the API is prone to break in future kernels.
 *    (This is also the reason why we're using attributes in the first place.
 *    the Generic Netlink API does not appear to want us to append payload
 *    unless it's enclosed in an attribute.)
 * b) Even if we could allocate room and modify the reserved chunk later, the
 *    operations where the buffer is most critical (database foreaches) don't
 *    know the size of the data they want to send before attempting to write it.
 *
 * So we use a buffer to build the attribute content first and write the
 * attribute later.
 *
 * TODO (later) maybe find a way to do this without attributes?
 */
struct jnl_buffer {
	__u16 len;
	__u16 capacity;
	void *data;
};

/* Buffer basic operations */
int jnlbuffer_init(struct jnl_buffer *buffer, struct genl_info *info,
		size_t capacity);
int jnlbuffer_init_max(struct jnl_buffer *buffer, struct genl_info *info);
int jnlbuffer_write(struct jnl_buffer *buffer, void *data, size_t data_size);
int jnlbuffer_send(struct jnl_buffer *buffer, struct genl_info *info);
void jnlbuffer_free(struct jnl_buffer *buffer);

/*
 * Utility functions
 * (Shorthands for declaring a buffer and doing something simple with it.)
 */
int jnl_respond_struct(struct genl_info *info, void *data, size_t len);
int jnl_respond(struct genl_info *info, int error);

#endif /* SRC_MODULE_COMMON_NL_NL_BUFFER_H_ */
