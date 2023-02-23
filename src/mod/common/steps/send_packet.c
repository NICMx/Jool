#include "send_packet.h"

#include "mod/common/linux_version.h"
#include "mod/common/log.h"
#include "mod/common/packet.h"
#include "mod/common/skbuff.h"

static void print_issue382(struct xlation *state, struct sk_buff *out,
		unsigned int idx)
{
	skb_log(state->in.skb, "EPERM in packet");
	pr_info("out packet index: %u", idx);
	pr_info("state flags: %x", state->debug_flags);
	skb_log(out, "EPERM out packet");
}

static verdict __sendpkt_send(struct xlation *state, struct sk_buff *out,
		unsigned int idx)
{
	struct dst_entry *dst;
	struct sk_buff *tmp;
	int error;

	dst = skb_dst(out);
	if (WARN(!dst, "dst is NULL!"))
		return drop(state, JSTAT_UNKNOWN);

	out->dev = dst->dev;
	log_debug(state, "Sending packet.");

	/* skb_log(out, "Translated packet"); */

	xlation_check_382(state, DBGFLAG_BAD_LEN_2, DBGFLAG_BAD_VERSION_2);
	tmp = skb_clone(out, GFP_ATOMIC);

	/* Implicit kfree_skb(out) here. */
	error = dst_output(state->jool.ns, NULL, out);
	if (error) {
		if (error == 1)
			print_issue382(state, tmp, idx);
		if (tmp)
			kfree_skb(tmp);

		log_debug(state, "dst_output() returned errcode %d.", error);
		return drop(state, JSTAT_DST_OUTPUT);
	}

	if (tmp)
		kfree_skb(tmp);
	return VERDICT_CONTINUE;
}

verdict sendpkt_send(struct xlation *state)
{
	struct sk_buff *skb;
	struct sk_buff *next;
	unsigned int idx;
	verdict result;

	idx = 0;
	for (skb = state->out.skb; skb != NULL; skb = next) {
		next = skb->next;
		skb->next = NULL;

		result = __sendpkt_send(state, skb, idx);
		if (result != VERDICT_CONTINUE) {
			kfree_skb_list(next);
			return result;
		}

		idx++;
	}

	return VERDICT_CONTINUE;
}
