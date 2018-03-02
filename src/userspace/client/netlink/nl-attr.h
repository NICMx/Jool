#ifndef SRC_USERSPACE_CLIENT_NETLINK_NL_ATTR_H_
#define SRC_USERSPACE_CLIENT_NETLINK_NL_ATTR_H_

#include <netlink/attr.h>
#include <netlink/msg.h>
#include "nl-protocol.h"

#define jnla_foreach_attr(attr, msg, rem) \
	nla_for_each_attr(attr, \
		genlmsg_attrdata(genlmsg_hdr(nlmsg_hdr(msg)), JNL_HDR_LEN), \
		genlmsg_attrlen(genlmsg_hdr(nlmsg_hdr(msg)), JNL_HDR_LEN), \
		rem)

int jnla_get_addr6(struct nlattr *attr, jool_nlattr type, struct in6_addr *addr);
int jnla_get_addr4(struct nlattr *attr, jool_nlattr type, struct in_addr *addr);
int jnla_get_port(struct nlattr *attr, jool_nlattr type, __u16 *result);
int jnla_get_bool(struct nlattr *attr, jool_nlattr type, bool *result);

struct nlattr *jnla_nested_first(struct nlattr *super_attr, int *remaining);
struct nlattr *jnla_next(struct nlattr *attr, int *remaining);

int jnla_put_addr6(struct nl_msg *msg, jool_nlattr type, struct in6_addr *addr);
int jnla_put_addr4(struct nl_msg *msg, jool_nlattr type, struct in_addr *addr);
int jnla_put_port(struct nl_msg *msg, jool_nlattr type, __u16 port);
int jnla_put_src_taddr6(struct nl_msg *msg, struct ipv6_transport_addr *addr);
int jnla_put_src_taddr4(struct nl_msg *msg, struct ipv4_transport_addr *addr);
int jnla_put_proto(struct nl_msg *request, l4_protocol proto);

#endif /* SRC_USERSPACE_CLIENT_NETLINK_NL_ATTR_H_ */
