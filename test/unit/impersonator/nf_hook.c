#include "nat64/mod/common/nf_hook.h"
#include "nat64/mod/common/nf_wrapper.h"

static NF_CALLBACK(hook_thingy, skb)
{
	return NF_ACCEPT;
}

void init_nf_hook_op6(struct nf_hook_ops *ops)
{
	memset(ops, 0, sizeof(*ops));
	ops->hook = hook_thingy;
	ops->pf = PF_INET6;
	ops->hooknum = NF_INET_PRE_ROUTING;
	ops->priority = NF_IP6_PRI_JOOL;
}

void init_nf_hook_op4(struct nf_hook_ops *ops)
{
	memset(ops, 0, sizeof(*ops));
	ops->hook = hook_thingy;
	ops->pf = PF_INET;
	ops->hooknum = NF_INET_PRE_ROUTING;
	ops->priority = NF_IP_PRI_JOOL;
}
