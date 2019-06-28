#include "mod/common/icmp_wrapper.h"

#include "mod/common/log.h"

/* The unit tests never spawn threads, so this does not need protection. */
static int sent = 0;

bool icmp64_send6(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	return icmp64_send(skb, error, info);
}

bool icmp64_send4(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	return icmp64_send(skb, error, info);
}

bool icmp64_send(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	log_debug("Pretending I'm sending an ICMP error.");
	sent++;
	return true;
}

int icmp64_pop(void)
{
	int result = sent;
	sent = 0;
	return result;
}
