#include "nat64/mod/icmp_wrapper.h"


void icmp64_send(struct fragment *frag, icmp_error_code code, __be32 info)
{
	log_debug("Pretending I'm sending a ICMP error.");
}

void icmp64_send_skb(struct sk_buff *skb, icmp_error_code code, __be32 info)
{
	log_debug("Pretending I'm sending a ICMP error.");
}
