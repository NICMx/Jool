#include "nat64/unit/send_packet.h"


static struct sk_buff *sent_skb = NULL;


int sendpkt_route4(struct sk_buff *skb)
{
	return 0;
}

int sendpkt_route6(struct sk_buff *skb)
{
	return 0;
}

verdict sendpkt_send(struct sk_buff *skb)
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
