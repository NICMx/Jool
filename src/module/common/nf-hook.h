#ifndef _JOOL_MOD_NF_HOOK_H
#define _JOOL_MOD_NF_HOOK_H

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#define NF_IP_PRI_JOOL (NF_IP_PRI_NAT_DST + 25)
#define NF_IP6_PRI_JOOL (NF_IP6_PRI_NAT_DST + 25)

void init_nf_hook_op6(struct nf_hook_ops *ops);
void init_nf_hook_op4(struct nf_hook_ops *ops);

#endif /* _JOOL_MOD_NF_HOOK_H */
