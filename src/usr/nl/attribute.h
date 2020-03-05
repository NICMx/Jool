#ifndef SRC_USR_NL_ATTRIBUTE_H_
#define SRC_USR_NL_ATTRIBUTE_H_

#include <netlink/attr.h>
#include "common/config.h"
#include "usr/util/result.h"

#define foreach_entry(pos, ghdr, rem) \
	nla_for_each_attr( \
		pos, \
		genlmsg_attrdata(ghdr, sizeof(struct request_hdr)), \
		genlmsg_attrlen(ghdr, sizeof(struct request_hdr)), \
		rem \
	)

struct jool_result jnla_parse_msg(struct nl_msg *msg, struct nlattr *tb[],
		int maxtype, struct nla_policy *policy,
		bool validate_mandatories);
struct jool_result jnla_parse_nested(struct nlattr *result[], int maxtype,
		struct nlattr *root, struct nla_policy *policy);

void nla_get_addr6(struct nlattr *attr, struct in6_addr *addr);
void nla_get_addr4(struct nlattr *attr, struct in_addr *addr);
struct jool_result nla_get_prefix6(struct nlattr *root, struct ipv6_prefix *out);
struct jool_result nla_get_prefix4(struct nlattr *root, struct ipv4_prefix *out);
struct jool_result nla_get_taddr6(struct nlattr *root, struct ipv6_transport_addr *out);
struct jool_result nla_get_taddr4(struct nlattr *root, struct ipv4_transport_addr *out);
struct jool_result nla_get_eam(struct nlattr *attr, struct eamt_entry *out);
struct jool_result nla_get_plateaus(struct nlattr *attr, struct mtu_plateaus *plateaus);

int nla_put_addr6(struct nl_msg *msg, int attrtype, struct in6_addr *addr);
int nla_put_addr4(struct nl_msg *msg, int attrtype, struct in_addr *addr);
int nla_put_prefix6(struct nl_msg *msg, int attrtype, struct ipv6_prefix *prefix);
int nla_put_prefix4(struct nl_msg *msg, int attrtype, struct ipv4_prefix *prefix);
int nla_put_taddr6(struct nl_msg *msg, int attrtype, struct ipv6_transport_addr *prefix);
int nla_put_taddr4(struct nl_msg *msg, int attrtype, struct ipv4_transport_addr *prefix);
int nla_put_plateaus(struct nl_msg *msg, int attrtype, struct mtu_plateaus *plateaus);

struct jool_result packet_too_small(void);

#endif /* SRC_USR_NL_ATTRIBUTE_H_ */
