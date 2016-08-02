#include "nat64/mod/common/icmp_wrapper.h"

static int sent = 0;

void icmp64_send4(struct sk_buff *skb, icmp_error_code error, __u32 info)
{
	icmp64_send(NULL, 0, 0);
}

void icmp64_send(struct packet *pkt, icmp_error_code code, __u32 info)
{
	log_debug("Pretending I'm sending an ICMP error.");
	sent++;
}

int icmp64_pop(void)
{
	int result = sent;
	sent = 0;
	return result;
}
