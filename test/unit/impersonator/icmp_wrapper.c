#include "mod/common/icmp_wrapper.h"

#include "mod/common/log.h"

bool icmp64_send6(struct xlator *jool, struct sk_buff *skb,
		icmp_error_code error, __u32 info)
{
	return icmp64_send(jool, skb, error, info);
}

bool icmp64_send4(struct xlator *jool, struct sk_buff *skb,
		icmp_error_code error, __u32 info)
{
	return icmp64_send(jool, skb, error, info);
}

bool icmp64_send(struct xlator *jool, struct sk_buff *skb,
		icmp_error_code error, __u32 info)
{
	pr_info("Pretending I'm sending an ICMP error.\n");
	return true;
}
