#ifndef SRC_MOD_COMMON_KERNEL_HOOK_H_
#define SRC_MOD_COMMON_KERNEL_HOOK_H_

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include "common/config.h"
#include "mod/common/nf_wrapper.h"

#define NF_IP_PRI_JOOL (NF_IP_PRI_NAT_DST + 25)
#define NF_IP6_PRI_JOOL (NF_IP6_PRI_NAT_DST + 25)

NF_CALLBACK(hook_ipv6, skb);
NF_CALLBACK(hook_ipv4, skb);

int target_checkentry(const struct xt_tgchk_param *param);
unsigned int target_ipv6(struct sk_buff *skb,
		const struct xt_action_param *param);
unsigned int target_ipv4(struct sk_buff *skb,
		const struct xt_action_param *param);

void init_nf_hook_op6(struct nf_hook_ops *ops);
void init_nf_hook_op4(struct nf_hook_ops *ops);

#endif /* SRC_MOD_COMMON_KERNEL_HOOK_H_ */
