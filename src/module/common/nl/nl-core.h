#ifndef __NL_CORE2_H__
#define __NL_CORE2_H__

#include <linux/skbuff.h>
#include <net/genetlink.h>
#include "types.h"
#include "xlator.h"

void nlcore_init(struct genl_family *new_family);
/* There's no nlcore_destroy; just destroy the family yourself. */

typedef int (*jnl_handler)(struct xlator *jool, struct genl_info *info);
int jnl_wrap_instance(struct genl_info *info, jnl_handler handler);


int jnla_put_l4proto(struct sk_buff *skb, l4_protocol proto);
int jnla_put_addr6(struct sk_buff *skb, jool_nlattr type, struct in6_addr *addr);
int jnla_put_addr4(struct sk_buff *skb, jool_nlattr type, struct in_addr *addr);
int jnla_put_src_taddr6(struct sk_buff *skb, struct ipv6_transport_addr *addr);
int jnla_put_src_taddr4(struct sk_buff *skb, struct ipv4_transport_addr *addr);
int jnla_put_dst_taddr6(struct sk_buff *skb, struct ipv6_transport_addr *addr);
int jnla_put_dst_taddr4(struct sk_buff *skb, struct ipv4_transport_addr *addr);
int jnla_put_port(struct sk_buff *skb, jool_nlattr type, __u16 port);
int jnla_put_prefix6(struct sk_buff *skb, struct ipv6_prefix *addr);
int jnla_put_prefix4(struct sk_buff *skb, struct ipv4_prefix *addr);
int jnla_put_bool(struct sk_buff *skb, jool_nlattr attrtype, bool value);

bool jnla_get_instance_name(struct genl_info *info, char **result);
bool jnla_get_l4proto(struct genl_info *info, l4_protocol *result);
bool jnla_get_src_taddr6(struct genl_info *info,
		struct ipv6_transport_addr *result);
bool jnla_get_src_taddr4(struct genl_info *info,
		struct ipv4_transport_addr *result);
bool jnla_get_dst_taddr6(struct genl_info *info,
		struct ipv6_transport_addr *result);
bool jnla_get_dst_taddr4(struct genl_info *info,
		struct ipv4_transport_addr *result);
bool jnla_get_port(struct genl_info *info, jool_nlattr type, __u16 *result);
bool jnla_get_prefix6(struct genl_info *info, struct ipv6_prefix *result);
bool jnla_get_prefix4(struct genl_info *info, struct ipv4_prefix *result);
bool jnla_get_u32(struct genl_info *info, jool_nlattr type, __u32 *result);
bool jnla_get_u8(struct genl_info *info, jool_nlattr type, __u8 *result);
bool jnla_get_bool(struct genl_info *info, jool_nlattr type, bool *result);


struct jnl_packet {
	struct sk_buff *skb;
	struct jnlmsghdr *jhdr;
};

#define JNL_MAX_PAYLOAD GENLMSG_DEFAULT_SIZE

int jnl_init_pkt(struct genl_info *info, size_t len, struct jnl_packet *pkt);
void jnl_destroy_pkt(struct jnl_packet *pkt);

int jnl_respond_pkt(struct genl_info *info, struct jnl_packet *pkt);
int jnl_respond_error(struct genl_info *info, int error);

#endif
