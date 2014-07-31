#include "nat64/mod/icmp_wrapper.h"
#include "nat64/mod/types.h"

static int sent = 0;

void icmp64_send(struct sk_buff *skb, icmp_error_code code, __be32 info)
{
	log_debug("Pretending I'm sending a ICMP error.");
	sent++;
}

int icmp64_pop(void)
{
	int result = sent;
	sent = 0;
	return result;
}
