#include "mod/common/steps/send_packet.h"

#include "mod/common/log.h"
#include "mod/common/packet.h"
#include "mod/common/nl/nl_handler.h"
/* #include "mod/common/skbuff.h" */

static void
log_pkt_sizes(struct xlation *state, struct sk_buff *skb)
{
	struct xlator *jool;
	struct sk_buff *frag;
	struct skb_shared_info *sh;

	jool = &state->jool;
	JOOL_DEBUG(jool, "Sending packet.");
	JOOL_DEBUG(jool, "  len:%u data_len:%u", skb->len, skb->data_len);

	sh = skb_shinfo(skb);
	if (!sh)
		return;

	JOOL_DEBUG(jool, "  nr_frags:%u gso_size:%u gso_segs:%u gso_type:%u",
	    sh->nr_frags, sh->gso_size, sh->gso_segs, sh->gso_type);
	skb_walk_frags(skb, frag) {
		JOOL_DEBUG(jool, "  - frag: len:%u data_len:%u",
		    frag->len, frag->data_len);

		sh = skb_shinfo(frag);
		if (!sh)
			continue;
		JOOL_DEBUG(jool,
		    "    nr_frags:%u gso_size:%u gso_segs:%u gso_type:%u",
		    sh->nr_frags, sh->gso_size, sh->gso_segs, sh->gso_type);
	}
}

static verdict __sendpkt_send(struct xlation *state, struct sk_buff *out)
{
	struct dst_entry *dst;
	int error;

	dst = skb_dst(out);
	if (WARN(!dst, "dst is NULL!"))
		return drop(state, JSTAT_UNKNOWN);

	out->dev = dst->dev;
	if (state_debug(state))
		log_pkt_sizes(state, out);

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

void sendpkt_multicast(struct xlator *jool, struct sk_buff *skb)
{
	int error;

	__log_debug(jool, "Sending multicast message.");
	/*
	 * Note: Starting from kernel 3.13, all groups of a common family share
	 * a group offset (from a common pool), and they are numbered
	 * monotonically from there. That means if all we have is one group,
	 * its id will always be zero.
	 *
	 * That's the reason why so many callers of this function stopped
	 * providing a group when the API started forcing them to provide a
	 * family.
	 */
	error = genlmsg_multicast_netns(jnl_family(), jool->ns, skb, 0, 0,
			GFP_ATOMIC);
	if (error) {
		log_warn_once("Looks like nobody received my multicast message. Is the joold daemon really active? (errcode %d)",
				error);
	} else {
		__log_debug(jool, "Multicast message sent.");
	}
}
