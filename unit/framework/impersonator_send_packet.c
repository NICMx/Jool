#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"


static struct sk_buff *sent_pkt = NULL;

bool send_packet_ipv4(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	log_debug("Step 6: Pretending I'm sending IPv4 packet %p...", skb_out);
	sent_pkt = skb_out;
	log_debug("Done step 6.");
	return true;
}

bool send_packet_ipv6(struct sk_buff *skb_in, struct sk_buff *skb_out)
{
	log_debug("Step 6: Pretending I'm sending IPv6 packet %p...", skb_out);
	sent_pkt = skb_out;
	log_debug("Done step 6.");
	return true;
}

struct sk_buff *get_sent_pkt(void)
{
	return sent_pkt;
}

void set_sent_pkt(struct sk_buff *skb)
{
	sent_pkt = skb;
}
