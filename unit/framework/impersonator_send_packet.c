#include "nat64/unit/send_packet_impersonator.h"
#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"


static struct sk_buff *sent_skb = NULL;


int route_ipv4(struct sk_buff *skb)
{
	return 0;
}

int route_ipv6(struct sk_buff *skb)
{
	return 0;
}

verdict send_pkt(struct sk_buff *skb)
{
	log_debug("Step 6: Pretending I'm sending packet %p...", skb);
	sent_skb = skb;
	log_debug("Done step 6.");
	return VER_CONTINUE;
}

struct sk_buff *get_sent_skb(void)
{
	return sent_skb;
}

void set_sent_skb(struct sk_buff *skb)
{
	sent_skb = skb;
}
