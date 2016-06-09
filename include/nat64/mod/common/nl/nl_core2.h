#ifndef __NL_CORE2_H__
#define __NL_CORE2_H__

#include <net/netlink.h>
#include <net/genetlink.h>
#include "nat64/common/config.h"

/**
 * Caller writes on the buffer. Once the buffer is full or the caller finishes
 * writing, the buffer is written into an skb and fetched.
 *
 * The caller does not work on the skb directly because:
 *
 * Rob had trouble making Generic Netlink work without attributes. It might be
 * impossible. We do not want to fetch attributes because we do not have any
 * warranty they will work the same in a different Linux kernel (which is
 * relevant in joold's case - the two NAT64s can be running in different
 * kernels). So what we did is use a single binary attribute. Userspace joold
 * unwraps the attribute and sends the binary data as is. The joold on the other
 * side should parse the data correctly because it is reasonable to expect
 * Jool's version to be the same.
 *
 * The problem with that is the binary blob needs to be ready by the time the
 * attribute is written into the packet. This is never the case for responses
 * to --display. In fact, it is also not true for joold.
 *
 * So we use a buffer to build the attribute content first and write the
 * attribute later.
 *
 * TODO (later) maybe find a way to do this without attributes?
 */
struct nlcore_buffer {
	__u16 len;
	__u16 capacity;
	void *data;
};

void nlcore_init(struct genl_family *new_family,
		struct genl_multicast_group *new_group);
/* There's no nlcore_destroy; just destroy the family yourself. */

size_t nlbuffer_response_max_size(void);
int nlbuffer_init_request(struct nlcore_buffer *buffer, struct request_hdr *hdr,
		size_t capacity);
int nlbuffer_init_response(struct nlcore_buffer *buffer, struct genl_info *info,
		size_t capacity);
void nlbuffer_free(struct nlcore_buffer *buffer);
int nlbuffer_write(struct nlcore_buffer *buffer, void *data, size_t data_size);
int nlbuffer_send(struct genl_info *info, struct nlcore_buffer *buffer);

void nlbuffer_set_pending_data(struct nlcore_buffer *buffer, bool pending_data);
void nlbuffer_set_errcode(struct nlcore_buffer *buffer, int error);

int nlcore_respond_struct(struct genl_info *info, void *content, size_t content_len);
int nlcore_respond(struct genl_info *info, int error);

int nlcore_send_multicast_message(struct net *ns, struct nlcore_buffer *buffer);

#endif
