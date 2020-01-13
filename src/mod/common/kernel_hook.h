#ifndef SRC_MOD_COMMON_KERNEL_HOOK_H_
#define SRC_MOD_COMMON_KERNEL_HOOK_H_

#include <linux/netfilter/x_tables.h>
#include "mod/common/nf_wrapper.h"
#include "mod/common/xlator.h"

/* Netfilter */
NF_CALLBACK(hook_ipv6, skb);
NF_CALLBACK(hook_ipv4, skb);

/* iptables/xtables */
int target_checkentry(const struct xt_tgchk_param *param);
unsigned int target_ipv6(struct sk_buff *skb,
		const struct xt_action_param *param);
unsigned int target_ipv4(struct sk_buff *skb,
		const struct xt_action_param *param);

/* nftables */
void nft_setup(void);
void nft_teardown(void);

/* iptables/xtables, nftables */
verdict find_instance_tb(struct net *ns, const struct target_info *info,
		struct xlator *result);

#endif /* SRC_MOD_COMMON_KERNEL_HOOK_H_ */
