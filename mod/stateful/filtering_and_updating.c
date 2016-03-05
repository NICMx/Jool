#include "nat64/mod/stateful/filtering_and_updating.h"

#include "nat64/common/session.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/bib/db.h"
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

static void log_bib(struct bib_entry *bib)
{
	if (bib)
		log_debug("BIB entry: %pI6c#%u - %pI4#%u (%s)",
				&bib->ipv6.l3, bib->ipv6.l4,
				&bib->ipv4.l3, bib->ipv4.l4,
				l4proto_to_string(bib->l4_proto));
	else
		log_debug("BIB entry: None");
}

static void log_session(struct session_entry *session)
{
	if (session)
		log_debug("Session entry: %pI6c#%u - %pI6c#%u | %pI4#%u - %pI4#%u (%s)",
				&session->remote6.l3, session->remote6.l4,
				&session->local6.l3, session->local6.l4,
				&session->local4.l3, session->local4.l4,
				&session->remote4.l3, session->remote4.l4,
				l4proto_to_string(session->l4_proto));
	else
		log_debug("Session entry: None");
}

static int xlat_addr64(struct xlation *state, struct in_addr *addr4)
{
	struct in6_addr *addr6 = &state->in.tuple.dst.addr6.l3;
	return rfc6052_6to4(state->jool.pool6, addr6, addr4);
}

static int create_bib6(struct xlation *state, struct bib_entry **result)
{
	struct ipv4_transport_addr saddr;
	struct in_addr daddr;
	struct bib_entry *bib;
	int error;

	error = xlat_addr64(state, &daddr);
	if (error)
		return error;
	error = palloc_allocate(state, &daddr, &saddr);
	if (error)
		return error;

	bib = bibentry_create(&saddr, &state->in.tuple.src.addr6, false,
			state->in.tuple.l4_proto);
	if (!bib) {
		log_debug("Failed to allocate a BIB entry.");
		return -ENOMEM;
	}

	*result = bib;
	return 0;
}

static int get_or_create_bib6(struct xlation *state, struct bib_entry **result)
{
	struct bib_entry *bib;
	int error;

	error = bibdb_find(state->jool.nat64.bib, &state->in.tuple, result);
	if (error != -ESRCH)
		return error; /* entry found and misc errors.*/

	/* entry not found. */
	error = create_bib6(state, &bib);
	if (error)
		return error;

	/*
	 * TODO (fine) this could be better.
	 * If somebody inserted a colliding BIB since we last searched,
	 * this will fail. Instead, it should fall back to use the already
	 * official entry.
	 * (Note: using the "old" argument is more trouble than it seems because
	 * this has to be handled differently depending on whether the collision
	 * was v4 or v6.)
	 */
	error = bibdb_add(state->jool.nat64.bib, bib, NULL);
	if (error) {
		bibentry_put_thread(bib, true);
		return error;
	}

	*result = bib;
	return 0;
}

static int create_session(struct xlation *state, struct bib_entry *bib,
		struct session_entry **result)
{
	struct tuple *tuple = &state->in.tuple;
	struct session_entry *session;
	struct ipv6_transport_addr remote6;
	struct ipv6_transport_addr local6;
	struct ipv4_transport_addr local4;
	struct ipv4_transport_addr remote4;
	int error;

	/*
	 * Fortunately, ICMP errors cannot reach this code because of the
	 * requirements in the header of section 3.5, so we can use the tuple
	 * as shortcuts for the packet's fields.
	 */
	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		remote6 = tuple->src.addr6;
		local6 = tuple->dst.addr6;
		local4 = bib->ipv4;
		error = xlat_addr64(state, &remote4.l3);
		if (error)
			return error;
		remote4.l4 = (tuple->l4_proto != L4PROTO_ICMP)
				? tuple->dst.addr6.l4
				: bib->ipv4.l4;
		break;
	case L3PROTO_IPV4:
		if (bib)
			remote6 = bib->ipv6;
		else
			/* Simultaneous Open (TCP quirk). */
			memset(&remote6, 0, sizeof(remote6));
		error = rfc6052_4to6(state->jool.pool6, &tuple->src.addr4.l3,
				&local6.l3);
		if (error)
			return error;
		local6.l4 = (tuple->l4_proto != L4PROTO_ICMP)
				? tuple->src.addr4.l4
				: bib->ipv6.l4;
		local4 = tuple->dst.addr4;
		remote4 = tuple->src.addr4;
		break;
	}

	session = session_create(&remote6, &local6, &local4, &remote4,
			tuple->l4_proto, bib);
	if (!session) {
		log_debug("Failed to allocate a session entry.");
		return -ENOMEM;
	}

	*result = session;
	return 0;
}

static enum session_fate update_timer(struct session_entry *session, void *arg)
{
	return FATE_TIMER_EST;
}

static int get_or_create_session(struct xlation *state, struct bib_entry *bib,
		struct session_entry **result)
{
	struct session_entry *session;
	int error;

	error = sessiondb_find(state->jool.nat64.session, &state->in.tuple,
			update_timer, NULL, result);
	if (error != -ESRCH)
		return error; /* entry found and misc errors.*/

	/* entry not found. */
	error = create_session(state, bib, &session);
	if (error)
		return error;

	error = sessiondb_add(state->jool.nat64.session, session, false,
			NULL, NULL);
	if (error) {
		session_put(session, true);
		return error;
	}

	*result = session;
	return 0;
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
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = get_or_create_bib6(state, &bib);
	if (error) {
		inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}
	log_bib(bib);

	error = get_or_create_session(state, bib, &session);
	if (error) {
		inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
		bibentry_put_thread(bib, false);
		return VERDICT_DROP;
	}
	log_session(session);

	/* Transfer session refcount to @state; do not put yet. */
	state->session = session;
	bibentry_put_thread(bib, false);

	return VERDICT_CONTINUE;
}

/**
 * Attempts to find "tuple"'s BIB entry and returns it in "bib".
 * Assumes "tuple" represents a IPv4 packet.
 */
static int get_bib4(struct xlation *state, struct bib_entry **bib)
{
	struct packet *in = &state->in;
	bool adf;
	int error;

	error = bibdb_find(state->jool.nat64.bib, &in->tuple, bib);
	if (error == -ESRCH) {
		log_debug("There is no BIB entry for the IPv4 packet.");
		inc_stats(in, IPSTATS_MIB_INNOROUTES);
		return error;
	} else if (error) {
		log_debug("Errcode %d while finding a BIB entry.", error);
		inc_stats(in, IPSTATS_MIB_INDISCARDS);
		icmp64_send(in, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	}

	adf = state->jool.global->cfg.nat64.drop_by_addr;
	if (adf && !sessiondb_allow(state->jool.nat64.session, &in->tuple)) {
		log_debug("Packet was blocked by address-dependent filtering.");
		icmp64_send(in, ICMPERR_FILTER, 0);
		inc_stats(in, IPSTATS_MIB_INDISCARDS);
		bibentry_put_thread(*bib, false);
		return -EPERM;
	}

	return 0;
}

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
	int error;
	struct bib_entry *bib;
	struct session_entry *session;

	error = get_bib4(state, &bib);
	if (error == -ESRCH)
		return VERDICT_ACCEPT;
	else if (error)
		return VERDICT_DROP;
	log_bib(bib);

	error = get_or_create_session(state, bib, &session);
	if (error) {
		inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
		bibentry_put_thread(bib, false);
		return VERDICT_DROP;
	}
	log_session(session);

	/* Transfer session refcount to @state; do not put yet. */
	state->session = session;
	bibentry_put_thread(bib, false);

	return VERDICT_CONTINUE;
}

/**
 * First half of the filtering and updating done during the CLOSED state of the
 * TCP state machine.
 * Processes IPv6 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_closed_v6_syn(struct xlation *state)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = get_or_create_bib6(state, &bib);
	if (error)
		goto simple_end;
	log_bib(bib);

	error = create_session(state, bib, &session);
	if (error)
		goto bib_end;
	session->state = V6_INIT;

	error = sessiondb_add(state->jool.nat64.session, session, false,
			NULL, NULL);
	if (error)
		goto session_end;

	log_session(session);
	/* Fall through. */

session_end:
	session_put(session, false);
bib_end:
	bibentry_put_thread(bib, false);
simple_end:
	return error;
}

/**
 * Second half of the filtering and updating done during the CLOSED state of the
 * TCP state machine.
 * Processes IPv4 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_v4_syn(struct xlation *state)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;
	verdict result = VERDICT_DROP;

	if (state->jool.global->cfg.nat64.drop_external_tcp) {
		log_debug("Applying policy: Dropping externally initiated TCP connections.");
		return VERDICT_DROP;
	}

	error = bibdb_find(state->jool.nat64.bib, &state->in.tuple, &bib);
	if (error) {
		if (error != -ESRCH)
			return VERDICT_DROP;
		bib = NULL;
	}
	log_bib(bib);

	error = create_session(state, bib, &session);
	if (error)
		goto end_bib;
	log_session(session);

	session->state = V4_INIT;

	if (!bib || state->jool.global->cfg.nat64.drop_by_addr) {
		error = pktqueue_add(&state->jool.nat64.session->pkt_queue,
				session, &state->in);
		if (error)
			goto end_session;

		/* skb's original skb completely belongs to pktqueue now. */
		result = VERDICT_STOLEN;

	} else {
		error = sessiondb_add(state->jool.nat64.session, session, false,
				NULL, NULL);
		if (error) {
			log_debug("Error code %d while adding the session to the DB.",
					error);
			goto end_session;
		}

		result = VERDICT_CONTINUE;
	}

	/* Fall through. */

end_session:
	session_put(session, false);
	/* Fall through. */

end_bib:
	if (bib)
		bibentry_put_thread(bib, false);
	return result;
}

/**
 * Filtering and updating done during the CLOSED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_state(struct xlation *state)
{
	struct packet *pkt = &state->in;
	struct bib_entry *bib;
	verdict result;
	int error;

	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV6:
		if (pkt_tcp_hdr(pkt)->syn) {
			result = is_error(tcp_closed_v6_syn(state))
					? VERDICT_DROP
					: VERDICT_CONTINUE;
			goto syn_out;
		}
		break;

	case L3PROTO_IPV4:
		if (pkt_tcp_hdr(pkt)->syn) {
			result = tcp_closed_v4_syn(state);
			goto syn_out;
		}
		break;
	}

	error = bibdb_find(state->jool.nat64.bib, &pkt->tuple, &bib);
	if (error) {
		log_debug("Closed state: Packet is not SYN and there is no BIB entry, so discarding. ERRcode %d",
				error);
		inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
		return VERDICT_DROP;
	}

	bibentry_put_thread(bib, false);
	return VERDICT_CONTINUE;

syn_out:
	if (result == VERDICT_DROP)
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
	return result;
}

static void joold_add(struct xlation *state, struct session_entry *session)
{
	joold_add_session(state->jool.nat64.session->joold, session);
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
		joold_add(state, session);
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
			joold_add(state, session);
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
			joold_add(state, session);
			break;
		case L3PROTO_IPV6:
			session->state = V6_FIN_RCV;
			joold_add(state, session);
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
		joold_add(state, session);
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
		joold_add(state, session);
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
		joold_add(state, session);
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
	if (error == -ESRCH)
		return tcp_closed_state(state);
	if (error) {
		log_debug("Error code %d while trying to find a TCP session.",
				error);
		inc_stats(&state->in, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}

	log_session(session);
	/* Transfer session refcount to @state; do not put yet. */
	state->session = session;
	return VERDICT_CONTINUE;
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
