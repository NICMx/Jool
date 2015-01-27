#include "nat64/unit/send_packet.h"


static struct sk_buff *sent_skb = NULL;


verdict sendpkt_send(struct sk_buff *in_skb, struct sk_buff *out_skb)
{
	log_debug("Step 6: Pretending I'm sending packet %p...", out_skb);
	sent_skb = out_skb;
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
