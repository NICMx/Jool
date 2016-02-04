#ifndef __NL_CORE2_H__
#define __NL_CORE2_H__

#include <net/netlink.h>
#include <net/genetlink.h>
#include "nat64/common/config.h"
#include "nat64/common/genetlink.h"

size_t nlbuffer_data_max_size(void);
int nlbuffer_new(struct nl_core_buffer **out_buffer, size_t size);
void nlbuffer_free(struct nl_core_buffer *buffer);
bool nlbuffer_write(struct nl_core_buffer *buffer, void *data, size_t data_length);
int nlbuffer_send(struct genl_info *info, enum config_mode command, struct nl_core_buffer *buffer);

int nlcore_respond_error(struct genl_info *info, enum config_mode command, int error_code);
int nlcore_respond_struct(struct genl_info *info, enum config_mode command,
		void *content, size_t content_len);
int nlcore_send_ack(struct genl_info *info, enum config_mode command);
int nlcore_respond(struct genl_info *info, enum config_mode command, int error);

void nlcore_set_main_callback(int (*cb)(struct sk_buff *skb_in, struct genl_info *info));
int nlcore_send_multicast_message(struct nl_core_buffer * buffer);

int nlcore_init(void);
void nlcore_destroy(void);

#endif
