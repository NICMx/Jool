#include "mod/common/steps/send_packet.h"

#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/packet.h"

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
#if LINUX_VERSION_AT_LEAST(4, 4, 0, 8, 0)
	error = dst_output(state->jool.ns, NULL, out);
#else
	error = dst_output(out);
#endif
	if (error) {
		log_debug(state, "dst_output() returned errcode %d.", error);
		return drop(state, JSTAT_DST_OUTPUT);
	}

	return VERDICT_CONTINUE;
}

#ifdef UNIT_TESTING
struct sk_buff *skb_out;
EXPORT_UNIT_SYMBOL(skb_out)
#endif

verdict sendpkt_send(struct xlation *state)
{
	struct sk_buff *skb;
	struct sk_buff *next;
	verdict result;

#ifdef UNIT_TESTING
	skb_out = state->out.skb;
	return VERDICT_CONTINUE;
#endif

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
EXPORT_UNIT_SYMBOL(sendpkt_send)
