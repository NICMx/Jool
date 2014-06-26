#include "nat64/mod/icmp_wrapper.h"
#include "nat64/mod/types.h"


void icmp64_send(struct sk_buff *skb, icmp_error_code code, __be32 info)
{
	log_debug("Pretending I'm sending a ICMP error.");
}
