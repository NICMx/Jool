#include "config.h"
#include "module-stats.h"
#include "send-packet.h"
#include "xlation.h"
#include "xlator.h"

#include "packet-init.h"
#include "nat64/determine-incoming-tuple.h"
#include "nat64/filtering-and-updating.h"
#include "nat64/compute-outgoing-tuple.h"
#include "rfc7915/core.h"
#include "handling-hairpinning.h"

static void core_common(struct xlation *state)
{
	int error;

	if (XLATOR_TYPE(state) == XLATOR_NAT64) {
		if (determine_in_tuple(state))
			return;
		if (filtering_and_updating(state))
			return;
		if (compute_out_tuple(state))
			return;
	}
	if (translating_the_packet(state))
		return;

	/* Both hh() and ss() release @state->out.skb regardless of error. */
	error = is_hairpin(state)
			? handling_hairpinning(state)
			: sendpkt_send(&state->out);
	if (error)
		return;

	log_debug("Success.");
	dev_kfree_skb(state->in.skb);
	state->in.skb = NULL; /* For check_skb_leak(). */
}

static void check_skb_leak(struct xlation *state, jstat_type type)
{
	if (unlikely(state->in.skb)) {
		log_warn_once("Memory leak detected. Please report at https://github.com/NICMx/Jool.");
		jstat_inc(state->jool.stats, type);
		/*
		 * I don't want to try to free the packet because there's always
		 * the chance that we might have actually remembered to
		 * deallocate but forgot to assign NULL.
		 * The kernel will die horribly if that happens. Rather have the
		 * memory leak.
		 */
	}
}

void core_4to6(struct xlator *jool, struct sk_buff *skb)
{
	struct xlation state;
	xlation_init(&state, jool);

	log_debug("Got IPv4 packet: %pI4->%pI4",
			&ip_hdr(skb)->saddr,
			&ip_hdr(skb)->daddr);

	/* Reminder: This function might change pointers. */
	if (pkt_init_ipv4(&state, skb))
		goto end;

	/*
	if (xlat_is_nat64(&state)) {
		if (ip_defrag(jool->ns, skb, DEFRAG4_JOOL_USER))
			return VERDICT_STOLEN;
	}
	*/

	core_common(&state);
	/* Fall through */

end:
	check_skb_leak(&state, JOOL_MIB_MEMLEAK46);
	xlation_put(&state);
}

void core_6to4(struct xlator *jool, struct sk_buff *skb)
{
	struct xlation state;
	xlation_init(&state, jool);

	snapshot_record(&state.in.debug.shot1, skb);

	log_debug("Got IPv6 packet: %pI6c->%pI6c",
			&ipv6_hdr(skb)->saddr,
			&ipv6_hdr(skb)->daddr);

	/* Reminder: This function might change pointers. */
	if (pkt_init_ipv6(&state, skb))
		goto end;

	snapshot_record(&state.in.debug.shot2, skb);

	/*
	 * TODO this is going to be a project.
	 *
	 * There are a few things that have always bothered me about the
	 * kernel's fragment reassembly code. Off the top of my head:
	 *
	 * - While the ip_defrag() API seems reasonably well-engineered in that
	 *   it seems designed to be reusable, the IPv6 defrag seems to be a
	 *   single-purpose gimmic. Perhaps as a result of only being used once,
	 *   its API seems to not be self-contained.
	 * - I don't think it's quite "fully well-engineered" because it relies
	 *   on an integer called "users", and there is no way for a kernel
	 *   module to acquire a 100% guaranteed unique value for this number.
	 *   This appears to be an unsolvable problem.
	 * - For some reason, the code sometimes reassembles in frags instead of
	 *   frag_list. I used to think I had this figured out, but later
	 *   experience revealed that I don't. I don't even see any usage of
	 *   frags in the code, so this baffles me to no end.
	 *   This essentially means that I haven't managed to nail defrag usage
	 *   correctly. Even the current most mature version of Jool likely has
	 *   quirks (issue #231).
	 * - Jool doesn't actually need the reassembly step. It just needs a
	 *   list with the fragments. They don't even need to be in the right
	 *   order. This makes fragment handling likely an order of complexity
	 *   slower than it needs to be.
	 * - They are miserably documented and poorly coded pieces of shit.
	 *   Seriously; I don't mind gotos in C, but the kernel devs seem to
	 *   outright have a fetish for them.
	 * - The kernel's official fragment representation is a bit of a pain to
	 *   work with.
	 *
	 * So I'm honestly wondering if it wouldn't be better to just roll-out
	 * my own defrag and call it a day. It would certainly be easier, but I
	 * would lose the official defrags' maturity.
	 */
	/*
	if (xlat_is_nat64(&state)) {
		result = fragdb_handle(state.jool.nat64.frag, &state.in);
		if (result != VERDICT_CONTINUE)
			goto end;
	}
	*/

	core_common(&state);
	/* Fall through */

end:
	check_skb_leak(&state, JOOL_MIB_MEMLEAK64);
	xlation_put(&state);
}
