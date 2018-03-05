#ifndef SRC_USERSPACE_CLIENT_NETLINK_NL_ATTR_H_
#define SRC_USERSPACE_CLIENT_NETLINK_NL_ATTR_H_

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include "nl-protocol.h"

#define jnla_foreach_attr(attr, msg, rem) \
	nla_for_each_attr(attr, \
		genlmsg_attrdata(genlmsg_hdr(nlmsg_hdr(msg)), JNL_HDR_LEN), \
		genlmsg_attrlen(genlmsg_hdr(nlmsg_hdr(msg)), JNL_HDR_LEN), \
		rem)

int jnla_get_addr6(struct nlattr *attr, jool_nlattr type, struct in6_addr *addr);
int jnla_get_addr4(struct nlattr *attr, jool_nlattr type, struct in_addr *addr);
int jnla_get_port(struct nlattr *attr, jool_nlattr type, __u16 *result);
int jnla_get_u64(struct nlattr *attr, jool_nlattr type, __u64 *result);
int jnla_get_u32(struct nlattr *attr, jool_nlattr type, __u32 *result);
int jnla_get_u8(struct nlattr *attr, jool_nlattr type, __u8 *result);
int jnla_get_l4proto(struct nlattr *attr, l4_protocol *result);
int jnla_get_bool(struct nlattr *attr, jool_nlattr type, bool *result);
int jnla_get_tcp_state(struct nlattr *attr, tcp_state *result);

struct nlattr *jnla_nested_first(struct nlattr *super_attr, int *remaining);
struct nlattr *jnla_next(struct nlattr *attr, int *remaining);

int jnla_put_addr6(struct nl_msg *msg, jool_nlattr type, struct in6_addr *addr);
int jnla_put_addr4(struct nl_msg *msg, jool_nlattr type, struct in_addr *addr);
int jnla_put_port(struct nl_msg *msg, jool_nlattr type, __u16 port);
int jnla_put_src_taddr6(struct nl_msg *msg, struct ipv6_transport_addr *addr);
int jnla_put_src_taddr4(struct nl_msg *msg, struct ipv4_transport_addr *addr);
int jnla_put_prefix6(struct nl_msg *msg, struct ipv6_prefix *prefix);
int jnla_put_prefix4(struct nl_msg *msg, struct ipv4_prefix *prefix);
int jnla_put_l4proto(struct nl_msg *request, l4_protocol proto);
int jnla_put_bool(struct nl_msg *request, jool_nlattr type, bool value);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_NL_ATTR_H_ */
