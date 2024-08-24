#include <linux/netfilter.h>
#include "mod/common/kernel_hook.h"

unsigned int hook_ipv6(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *nhs)
{
	return NF_ACCEPT;
}

unsigned int hook_ipv4(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *nhs)
{
	return NF_ACCEPT;
}
