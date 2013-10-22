#include "nat64/unit/send_packet_impersonator.h"
#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"


static struct sk_buff *sent_skb = NULL;


struct dst_entry *route_ipv4(struct iphdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	return NULL;
}

struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	return NULL;
}

verdict send_pkt(struct packet *pkt)
{
	log_debug("Step 6: Pretending I'm sending packet %p...", pkt);
	sent_skb = pkt->first_fragment->skb;
	pkt->first_fragment->skb = NULL;
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
