#ifndef __NL_CORE2_H__
#define __NL_CORE2_H__

#include <net/netlink.h>
#include <net/genetlink.h>
#include "nat64/common/config.h"
#include "nat64/common/genetlink.h"

size_t nl_core_data_max_size(void);
int nl_core_new_core_buffer(struct nl_core_buffer **out_buffer, size_t size);
void nl_core_free_buffer(struct nl_core_buffer *buffer);
bool nl_core_write_to_buffer(struct nl_core_buffer *buffer, __u8 *data, size_t data_length);
int nl_core_send_buffer(struct genl_info *info, enum config_mode command, struct nl_core_buffer *buffer);
int nl_core_respond_error(struct genl_info *info, enum config_mode command, int error_code);
int nl_core_send_acknowledgement(struct genl_info *info, enum config_mode command);
int nl_core_register_mc_group(struct genl_multicast_group *grp);
void nl_core_set_main_callback(int (*cb)(struct sk_buff *skb_in, struct genl_info *info));
int nl_core_send_multicast_message(struct nl_core_buffer * buffer, struct genl_multicast_group *grp);
int nl_core_init(void);
int nl_core_destroy(void);

#endif
