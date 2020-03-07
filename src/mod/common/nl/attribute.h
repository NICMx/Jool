#ifndef SRC_MOD_COMMON_NL_ATTRIBUTE_H_
#define SRC_MOD_COMMON_NL_ATTRIBUTE_H_

#include <linux/netlink.h>
#include "common/config.h"

int jnla_get_u8(struct nlattr *attr, char const *name, __u8 *out);
int jnla_get_u32(struct nlattr *attr, char const *name, __u32 *out);
int jnla_get_str(struct nlattr *attr, char const *name, size_t len, char *out);
int jnla_get_addr6(struct nlattr *attr, char const *name, struct in6_addr *out);
int jnla_get_addr4(struct nlattr *attr, char const *name, struct in_addr *out);
int jnla_get_prefix6(struct nlattr *attr, char const *name, struct ipv6_prefix *out);
int jnla_get_prefix4(struct nlattr *attr, char const *name, struct ipv4_prefix *out);
int jnla_get_taddr6(struct nlattr *attr, char const *name, struct ipv6_transport_addr *out);
int jnla_get_taddr4(struct nlattr *attr, char const *name, struct ipv4_transport_addr *out);
int jnla_get_eam(struct nlattr *attr, char const *name, struct eamt_entry *eam);
int jnla_get_pool4(struct nlattr *attr, char const *name, struct pool4_entry *entry);
int jnla_get_bib(struct nlattr *attr, char const *name, struct bib_entry *entry);
int jnla_get_plateaus(struct nlattr *attr, struct mtu_plateaus *out);

/* Note: None of these print error messages. */
int jnla_put_addr6(struct sk_buff *skb, int attrtype, struct in6_addr const *addr);
int jnla_put_addr4(struct sk_buff *skb, int attrtype, struct in_addr const *addr);
int jnla_put_prefix6(struct sk_buff *skb, int attrtype, struct ipv6_prefix const *prefix);
int jnla_put_prefix4(struct sk_buff *skb, int attrtype, struct ipv4_prefix const *prefix);
int jnla_put_taddr6(struct sk_buff *skb, int attrtype, struct ipv6_transport_addr const *prefix);
int jnla_put_taddr4(struct sk_buff *skb, int attrtype, struct ipv4_transport_addr const *prefix);
int jnla_put_eam(struct sk_buff *skb, int attrtype, struct eamt_entry const *eam);
int jnla_put_pool4(struct sk_buff *skb, int attrtype, struct pool4_entry const *bib);
int jnla_put_bib(struct sk_buff *skb, int attrtype, struct bib_entry const *bib);
int jnla_put_session(struct sk_buff *skb, int attrtype, struct session_entry_usr const *entry);
int jnla_put_plateaus(struct sk_buff *skb, int attrtype, struct mtu_plateaus const *plateaus);

void report_put_failure(void);

#endif /* SRC_MOD_COMMON_NL_ATTRIBUTE_H_ */
