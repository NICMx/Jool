#include "send_packet.h"

#include "mod/common/log.h"
#include "mod/common/packet.h"
/* #include "mod/common/skbuff.h" */

static verdict __sendpkt_send(struct xlation *state, struct sk_buff *out)
{
	struct dst_entry *dst;
	int error;

	dst = skb_dst(out);
	if (WARN(!dst, "dst is NULL!"))
		return drop(state, JSTAT_UNKNOWN);

	out->dev = dst->dev;
	log_debug(state, "Sending packet.");

	/* skb_log(out, "Translated packet"); */

	/* Implicit kfree_skb(out) here. */
	error = dst_output(state->jool.ns, NULL, out);
	if (error) {
		log_debug(state, "dst_output() returned errcode %d.", error);
		return drop(state, JSTAT_DST_OUTPUT);
	}

	return VERDICT_CONTINUE;
}

verdict sendpkt_send(struct xlation *state)
{
	struct sk_buff *skb;
	struct sk_buff *next;
	verdict result;

	for (skb = state->out.skb; skb != NULL; skb = next) {
		next = skb->next;
		skb->next = NULL;

		result = __sendpkt_send(state, skb);
		if (result != VERDICT_CONTINUE) {
			kfree_skb_list(next);
			return result;
		}
	}

	return VERDICT_CONTINUE;
}
