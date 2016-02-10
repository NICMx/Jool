#ifndef __NL_CORE2_H__
#define __NL_CORE2_H__

#include <net/netlink.h>
#include <net/genetlink.h>
#include "nat64/common/config.h"
#include "nat64/common/genetlink.h"

size_t nlbuffer_data_max_size(void);
int nlbuffer_init(struct nlcore_buffer *buffer, struct genl_info *info,
		size_t capacity);
void nlbuffer_free(struct nlcore_buffer *buffer);
bool nlbuffer_write(struct nlcore_buffer *buffer, void *data, size_t data_size);
int nlbuffer_send(struct genl_info *info, struct nlcore_buffer *buffer);

void nlbuffer_set_pending_data(struct nlcore_buffer *buffer, bool pending_data);
void nlbuffer_set_errcode(struct nlcore_buffer *buffer, int error);

int nlcore_respond_error(struct genl_info *info, int error_code);
int nlcore_respond_struct(struct genl_info *info, void *content, size_t content_len);
int nlcore_send_ack(struct genl_info *info);
int nlcore_respond(struct genl_info *info, int error);

int nlcore_send_multicast_message(struct nlcore_buffer * buffer);

int nlcore_init(void);
void nlcore_destroy(void);

#endif
