#include "nat64/mod/stateful/filtering_and_updating.h"

#include "nat64/common/str_utils.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/bib/entry.h"
#include "nat64/mod/stateful/bib/port_allocator.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>
#include <net/tcp.h>
#include <net/icmp.h>

enum session_fate tcp_expired_cb(struct session_entry *session, void *arg)
{
	switch (session->state) {
	case ESTABLISHED:
		session->state = TRANS;
		session->update_time = jiffies;
		return FATE_PROBE;

	case V4_INIT:
	case V6_INIT:
	case V4_FIN_RCV:
	case V6_FIN_RCV:
	case V4_FIN_V6_FIN_RCV:
	case TRANS:
		session->state = CLOSED;
		return FATE_RM;

	case CLOSED:
		/* Closed sessions must not be stored; this is an error. */
		WARN(true, "Closed state found; removing session entry.");
		return FATE_RM;
	}

	WARN(true, "Unknown state found (%d); removing session entry.",
			session->state);
	return FATE_RM;
}

static void log_session(struct session_entry *session)
{
	char const *proto;

	if (!session) {
		log_debug("BIB entry: None");
		log_debug("Session entry: None");
		return;
	}

	proto = l4proto_to_string(session->l4_proto);
	log_debug("BIB entry: %pI6c#%u - %pI4#%u (%s)",
			&session->src6.l3, session->src6.l4,
			&session->src4.l3, session->src4.l4,
			proto);
	log_debug("Session entry: %pI6c#%u - %pI6c#%u | %pI4#%u - %pI4#%u (%s)",
			&session->src6.l3, session->src6.l4,
			&session->dst6.l3, session->dst6.l4,
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4,
			proto);
}

static verdict succeed(struct xlation *state, struct session_entry *session)
{
	log_session(session);
	/*
	 * Sometimes the session doesn't change as a result of the state
	 * machine's schemes.
	 * No state change, no timeout change, no update time change.
	 *
	 * One might argue that we shouldn't joold the session in those cases.
	 * It's a lot more trouble than it's worth:
	 *
	 * - Calling joold_add() on the TCP SM state functions is incorrect
	 *   because the session's update_time and expirer haven't been updated
	 *   by that point. So what gets synchronizes is half-baked data.
	 * - Calling joold_add() on decide_fate() is a freaking mess because
	 *   we'd need to send the xlator and a boolean (indicating whether this
	 *   is packet or timer context) to it and all intermediate functions,
	 *   and these functions all already have too many arguments as it is.
	 *   It's bad design anyway; the session module belongs to a layer that
	 *   shouldn't be aware of the xlator.
	 * - These special no-changes cases are rare.
	 *
	 * So let's simplify everything by just joold_add()ing here.
	 */
	joold_add(state->jool.nat64.joold, session, state->jool.nat64.session);
	/* Transfer session refcount to @state; do not put yet. */
	state->session = session;
	return VERDICT_CONTINUE;
}

static verdict breakdown(struct xlation *state)
{
	inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
	return VERDICT_DROP;
}

static struct session_entry *create_session(struct xlation *state,
		struct bib_entry *bib, tcp_state sm_state)
{
	struct tuple *tuple = &state->in.tuple;
	struct session_entry *session;
	struct ipv6_transport_addr src6;
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;

	/*
	 * Fortunately, ICMP errors cannot reach this code because of the
	 * requirements in the header of section 3.5, so we can use the tuple
	 * as shortcuts for the packet fields.
	 */
	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		src6 = tuple->src.addr6;
		dst6 = tuple->dst.addr6;

		if (rfc6052_6to4(state->jool.pool6, &tuple->dst.addr6.l3,
				&dst4.l3))
			return NULL;

		if (palloc_allocate(state, &dst4.l3, &src4))
			return NULL;

		dst4.l4 = (tuple->l4_proto != L4PROTO_ICMP)
				? tuple->dst.addr6.l4
				: src4.l4;
		break;
	case L3PROTO_IPV4:
		if (bib)
			src6 = bib->ipv6;
		else
			/* Simultaneous Open (TCP quirk). */
			memset(&src6, 0, sizeof(src6));
		if (rfc6052_4to6(state->jool.pool6, &tuple->src.addr4.l3,
				&dst6.l3))
			return NULL;
		dst6.l4 = (tuple->l4_proto != L4PROTO_ICMP)
				? tuple->src.addr4.l4
				: src6.l4;
		src4 = tuple->dst.addr4;
		dst4 = tuple->src.addr4;
		break;
	}

	session = session_create(&src6, &dst6, &src4, &dst4, tuple->l4_proto);
	if (!session)
		return NULL;
	session->state = sm_state;
	return session;
}

static enum session_fate update_timer(struct session_entry *session, void *arg)
{
	return FATE_TIMER_EST;
}

static verdict create_and_add_session(struct xlation *state, tcp_state sm_state,
		bool est)
{
	struct session_entry *session;

	session = create_session(state, NULL, sm_state);
	if (!session)
		return breakdown(state);

	/*
	 * TODO (fine) this could be better.
	 * If somebody inserted a colliding entry since we last searched, this
	 * will fail. Instead, it should fall back to use the already official
	 * entry.
	 * (Note: using the "old" argument is more trouble than it seems because
	 * this has to be handled differently depending on whether the collision
	 * was v4, v6 or v64.)
	 */
	if (sessiondb_add_simple(state->jool.nat64.session, session, est)) {
		session_put(session, true);
		return breakdown(state);
	}

	return succeed(state, session);
}

/**
 * Assumes that "tuple" represents a IPv6-UDP or ICMP packet, and filters and
 * updates based on it.
 *
 * This is RFC 6146, first halves of both sections 3.5.1 and 3.5.3.
 *
 * @pkt: tuple's packet. This is actually only used for error reporting.
 * @tuple: summary of the packet Jool is currently translating.
 */
static verdict ipv6_simple(struct xlation *state)
{
	struct session_entry *session;
	int error;

	error = sessiondb_find(state->jool.nat64.session, &state->in.tuple,
			update_timer, NULL, &session);
	switch (error) {
	case 0:
		return succeed(state, session);
	case -ESRCH:
		return create_and_add_session(state, ESTABLISHED, true);
	default:
		return breakdown(state);
	}
}

///**
// * Attempts to find "tuple"'s BIB entry and returns it in "bib".
// * Assumes "tuple" represents a IPv4 packet.
// */
//static int get_bib4(struct xlation *state, struct bib_entry **bib)
//{
////	TODO
//	struct packet *in = &state->in;
//	bool adf;
//	int error;
//
//	error = bibdb_find(state->jool.nat64.bib, &in->tuple, bib);
//	if (error == -ESRCH) {
//		log_debug("There is no BIB entry for the IPv4 packet.");
//		inc_stats(in, IPSTATS_MIB_INNOROUTES);
//		return error;
//	} else if (error) {
//		log_debug("Errcode %d while finding a BIB entry.", error);
//		inc_stats(in, IPSTATS_MIB_INDISCARDS);
//		icmp64_send(in, ICMPERR_ADDR_UNREACHABLE, 0);
//		return error;
//	}
//
//	adf = state->jool.global->cfg.nat64.drop_by_addr;
//	if (adf && !sessiondb_allow(state->jool.nat64.session, &in->tuple)) {
//		log_debug("Packet was blocked by address-dependent filtering.");
//		icmp64_send(in, ICMPERR_FILTER, 0);
//		inc_stats(in, IPSTATS_MIB_INDISCARDS);
//		bibentry_put_thread(*bib, false);
//		return -EPERM;
//	}
//
//	return 0;
//}

/**
 * Assumes that "tuple" represents a IPv4-UDP or ICMP packet, and filters and
 * updates based on it.
 *
 * This is RFC 6146, second halves of both sections 3.5.1 and 3.5.3.
 *
 * @pkt skb tuple's packet. This is actually only used for error reporting.
 * @tuple4 tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv4_simple(struct xlation *state)
{
	struct bib_entry bib;
	struct session_entry *session;
	bool allow;
	int error;

	error = sessiondb_find_full(state->jool.nat64.session, &state->in.tuple,
			&bib, &session, &allow);
	switch (error) {
	case 0:
		break;
	case -ESRCH:
		log_debug("There is no BIB entry for the IPv4 packet.");
		inc_stats(&state->in, IPSTATS_MIB_INNOROUTES);
		return VERDICT_ACCEPT;
	default:
		log_debug("Errcode %d while finding a BIB entry.", error);
		inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
		icmp64_send(&state->in, ICMPERR_ADDR_UNREACHABLE, 0);
		return breakdown(state);
	}

	if (state->jool.global->cfg.nat64.drop_by_addr && !allow) {
		log_debug("Packet was blocked by address-dependent filtering.");
		icmp64_send(&state->in, ICMPERR_FILTER, 0);
		inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
		return -EPERM;
	}

	if (session)
		return succeed(state, session);

	session = create_session(state, &bib, ESTABLISHED);
	if (!session)
		return breakdown(state);
	if (sessiondb_add_simple(state->jool.nat64.session, session, true)) {
		session_put(session, true);
		return breakdown(state);
	}
	return succeed(state, session);
}

/**
 * First half of the filtering and updating done during the CLOSED state of the
 * TCP state machine.
 * Processes IPv6 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_v6_syn(struct xlation *state)
{
	return create_and_add_session(state, V6_INIT, false);
}

static verdict send_session_to_pktqueue(struct xlation *state,
		struct bib_entry *bib)
{
	struct session_entry *session;

	session = create_session(state, bib, V4_INIT);
	if (!session)
		return breakdown(state);

	if (sessiondb_queue(state->jool.nat64.session, session, &state->in)) {
		session_put(session, true);
		return breakdown(state);
	}

	/* The original skb belongs to pktqueue now. */
	/* Also do not put the session; the kref was transferred. */
	return VERDICT_STOLEN;
}

/**
 * Second half of the filtering and updating done during the CLOSED state of the
 * TCP state machine.
 * Processes IPv4 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_v4_syn(struct xlation *state)
{
	struct bib_entry bib;
	struct session_entry *session;

	if (state->jool.global->cfg.nat64.drop_external_tcp) {
		log_debug("Applying policy: Drop externally initiated TCP connections.");
		return breakdown(state);
	}

	switch (sessiondb_find_bib_by_tuple(state->jool.nat64.session,
			&state->in.tuple, &bib)) {
	case 0:
		break;
	case -ESRCH:
		return send_session_to_pktqueue(state, NULL);
	default:
		return breakdown(state);
	}

	if (state->jool.global->cfg.nat64.drop_by_addr)
		return send_session_to_pktqueue(state, &bib);

	session = create_session(state, &bib, V4_INIT);
	if (!session)
		return breakdown(state);
	if (sessiondb_add_simple(state->jool.nat64.session, session, false)) {
		session_put(session, true);
		return breakdown(state);
	}

	return succeed(state, session);
}

/**
 * Filtering and updating done during the CLOSED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_state(struct xlation *state)
{
	struct packet *pkt = &state->in;
	int error;

	if (pkt_tcp_hdr(pkt)->syn) {
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV6:
			return tcp_closed_v6_syn(state);
		case L3PROTO_IPV4:
			return tcp_closed_v4_syn(state);
		}
	}

	error = sessiondb_find_bib_by_tuple(state->jool.nat64.session,
			&pkt->tuple, NULL);
	if (error) {
		log_debug("Closed state: Packet is not SYN and there is no BIB entry, so discarding. ERRcode %d",
				error);
		inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
		/* TODO wth? should this not be an ACCEPT? */
		return VERDICT_DROP;
	}

	return VERDICT_CONTINUE;
}

/**
 * Filtering and updating during the V4 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static enum session_fate tcp_v4_init_state(struct session_entry *session,
		struct xlation *state)
{
	struct packet *pkt = &state->in;

	if (pkt_l3_proto(pkt) == L3PROTO_IPV6 && pkt_tcp_hdr(pkt)->syn) {
		session->state = ESTABLISHED;
		return FATE_TIMER_EST;
	}

	return FATE_PRESERVE;
}

/**
 * Filtering and updating during the V6 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static enum session_fate tcp_v6_init_state(struct session_entry *session,
		struct xlation *state)
{
	struct packet *pkt = &state->in;

	if (pkt_tcp_hdr(pkt)->syn) {
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV4:
			session->state = ESTABLISHED;
			return FATE_TIMER_EST;
		case L3PROTO_IPV6:
			return FATE_TIMER_TRANS;
		}
	}

	return FATE_PRESERVE;
}

/**
 * Filtering and updating during the ESTABLISHED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static enum session_fate tcp_established_state(struct session_entry *session,
		struct xlation *state)
{
	struct packet *pkt = &state->in;

	if (pkt_tcp_hdr(pkt)->fin) {
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV4:
			session->state = V4_FIN_RCV;
			break;
		case L3PROTO_IPV6:
			session->state = V6_FIN_RCV;
			break;
		}
		return FATE_PRESERVE;

	} else if (pkt_tcp_hdr(pkt)->rst) {
		session->state = TRANS;
		return FATE_TIMER_TRANS;
	}

	return FATE_TIMER_EST;
}

/**
 * Filtering and updating during the V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static enum session_fate tcp_v4_fin_rcv_state(struct session_entry *session,
		struct xlation *state)
{
	struct packet *pkt = &state->in;

	if (pkt_l3_proto(pkt) == L3PROTO_IPV6 && pkt_tcp_hdr(pkt)->fin) {
		session->state = V4_FIN_V6_FIN_RCV;
		return FATE_TIMER_TRANS;
	}

	return FATE_TIMER_EST;
}

/**
 * Filtering and updating during the V6 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static enum session_fate tcp_v6_fin_rcv_state(struct session_entry *session,
		struct xlation *state)
{
	struct packet *pkt = &state->in;

	if (pkt_l3_proto(pkt) == L3PROTO_IPV4 && pkt_tcp_hdr(pkt)->fin) {
		session->state = V4_FIN_V6_FIN_RCV;
		return FATE_TIMER_TRANS;
	}

	return FATE_TIMER_EST;
}

/**
 * Filtering and updating during the V6 FIN + V4 FIN RCV state of the TCP state
 * machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static enum session_fate tcp_v4_fin_v6_fin_rcv_state(void)
{
	return FATE_PRESERVE; /* Only the timeout can change this state. */
}

/**
 * Filtering and updating done during the TRANS state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static enum session_fate tcp_trans_state(struct session_entry *session,
		struct xlation *state)
{
	struct packet *pkt = &state->in;

	if (!pkt_tcp_hdr(pkt)->rst) {
		session->state = ESTABLISHED;
		return FATE_TIMER_EST;
	}

	return FATE_PRESERVE;
}

static enum session_fate tcp_state_machine(struct session_entry *session,
		void *arg)
{
	switch (session->state) {
	case V4_INIT:
		return tcp_v4_init_state(session, arg);
	case V6_INIT:
		return tcp_v6_init_state(session, arg);
	case ESTABLISHED:
		return tcp_established_state(session, arg);
	case V4_FIN_RCV:
		return tcp_v4_fin_rcv_state(session, arg);
	case V6_FIN_RCV:
		return tcp_v6_fin_rcv_state(session, arg);
	case V4_FIN_V6_FIN_RCV:
		return tcp_v4_fin_v6_fin_rcv_state();
	case TRANS:
		return tcp_trans_state(session, arg);
	case CLOSED:
		break;
	}

	/*
	 * Because closed sessions are not supposed to be stored,
	 * CLOSED is known to fall through here.
	 */
	WARN(true, "Invalid state found: %u.", session->state);
	return FATE_RM;
}

/**
 * Assumes that "tuple" represents a TCP packet, and filters and updates based
 * on it. Encapsulates the TCP state machine.
 *
 * This is RFC 6146 section 3.5.2.
 */
static verdict tcp(struct xlation *state)
{
	struct session_entry *session;
	int error;

	error = sessiondb_find(state->jool.nat64.session, &state->in.tuple,
			tcp_state_machine, state, &session);
	switch (error) {
	case 0:
		return succeed(state, session);
	case -ESRCH:
		return tcp_closed_state(state);
	default:
		return breakdown(state);
	}
}

/**
 * filtering_and_updating - Main F&U routine. Decides if "skb" should be
 * processed, updating binding and session information.
 */
verdict filtering_and_updating(struct xlation *state)
{
	struct packet *in = &state->in;
	struct ipv6hdr *hdr_ip6;
	verdict result = VERDICT_CONTINUE;

	log_debug("Step 2: Filtering and Updating");

	switch (pkt_l3_proto(in)) {
	case L3PROTO_IPV6:
		/* Get rid of hairpinning loops and unwanted packets. */
		hdr_ip6 = pkt_ip6_hdr(in);
		if (pool6_contains(state->jool.pool6, &hdr_ip6->saddr)) {
			log_debug("Hairpinning loop. Dropping...");
			inc_stats(in, IPSTATS_MIB_INADDRERRORS);
			return VERDICT_DROP;
		}
		if (!pool6_contains(state->jool.pool6, &hdr_ip6->daddr)) {
			log_debug("Packet does not belong to pool6.");
			return VERDICT_ACCEPT;
		}

		/* ICMP errors should not be filtered or affect the tables. */
		if (pkt_is_icmp6_error(in)) {
			log_debug("Packet is ICMPv6 error; skipping step...");
			return VERDICT_CONTINUE;
		}
		break;
	case L3PROTO_IPV4:
		/* Get rid of unexpected packets */
		if (!pool4db_contains(state->jool.nat64.pool4, state->jool.ns,
				in->tuple.l4_proto, &in->tuple.dst.addr4)) {
			log_debug("Packet does not belong to pool4.");
			return VERDICT_ACCEPT;
		}

		/* ICMP errors should not be filtered or affect the tables. */
		if (pkt_is_icmp4_error(in)) {
			log_debug("Packet is ICMPv4 error; skipping step...");
			return VERDICT_CONTINUE;
		}
		break;
	}

	switch (pkt_l4_proto(in)) {
	case L4PROTO_UDP:
		switch (pkt_l3_proto(in)) {
		case L3PROTO_IPV6:
			result = ipv6_simple(state);
			break;
		case L3PROTO_IPV4:
			result = ipv4_simple(state);
			break;
		}
		break;

	case L4PROTO_TCP:
		result = tcp(state);
		break;

	case L4PROTO_ICMP:
		switch (pkt_l3_proto(in)) {
		case L3PROTO_IPV6:
			if (state->jool.global->cfg.nat64.drop_icmp6_info) {
				log_debug("Packet is ICMPv6 info (ping); dropping due to policy.");
				inc_stats(in, IPSTATS_MIB_INDISCARDS);
				return VERDICT_DROP;
			}

			result = ipv6_simple(state);
			break;
		case L3PROTO_IPV4:
			result = ipv4_simple(state);
			break;
		}
		break;

	case L4PROTO_OTHER:
		WARN(true, "Unknown layer 4 protocol: %d", pkt_l4_proto(in));
		result = VERDICT_DROP;
		break;
	}

	log_debug("Done: Step 2.");
	return result;
}
