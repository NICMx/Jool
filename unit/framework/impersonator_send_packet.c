#include "nat64/mod/send_packet.h"
#include "nat64/comm/types.h"


static struct packet *sent_pkt = NULL;


struct dst_entry *route_ipv4(struct iphdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	return NULL;
}

struct dst_entry *route_ipv6(struct ipv6hdr *hdr_ip, void *l4_hdr, l4_protocol l4_proto, u32 mark)
{
	return NULL;
}

enum verdict send_pkt(struct packet *pkt)
{
	log_debug("Step 6: Pretending I'm sending packet %p...", pkt);
	sent_pkt = pkt;
	log_debug("Done step 6.");
	return VER_CONTINUE;
}

/*
struct packet *get_sent_pkt(void)
{
	return sent_pkt;
}

void set_sent_pkt(struct packet *skb)
{
	sent_pkt = skb;
}
*/
