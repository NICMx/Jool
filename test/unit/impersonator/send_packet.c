#include "framework/send_packet.h"

#include "mod/common/log.h"

struct sk_buff *skb_out = NULL;

verdict sendpkt_send(struct xlation *state)
{
	pr_info("Pretending I'm sending a packet.\n");
	skb_out = state->out.skb;
	return VERDICT_CONTINUE;
}
