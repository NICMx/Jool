#include "nat64/unit/send_packet.h"


static struct sk_buff *sent_skb = NULL;


verdict sendpkt_send(struct packet *in, struct packet *out)
{
	log_debug("Step 6: Pretending I'm sending packet %p...", out);
	sent_skb = out->skb;
	log_debug("Done step 6.");
	return VERDICT_CONTINUE;
}

struct sk_buff *get_sent_skb(void)
{
	return sent_skb;
}

void set_sent_skb(struct sk_buff *skb)
{
	sent_skb = skb;
}
