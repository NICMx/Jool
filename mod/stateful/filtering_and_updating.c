#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/bib/port_allocator.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/session/db.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>
#include <net/tcp.h>
#include <net/icmp.h>


/**
 * Decides whether the packet should be filtered or not.
 */
static inline void apply_policies(void)
{
	/* No code. iptables does this for us :p. */
}

static void log_bib(struct bib_entry *bib)
{
	if (bib)
		log_debug("BIB entry: %pI6c#%u - %pI4#%u",
				&bib->ipv6.l3, bib->ipv6.l4,
				&bib->ipv4.l3, bib->ipv4.l4);
	else
		log_debug("BIB entry: None");
}

static void log_session(struct session_entry *session)
{
	if (session)
		log_debug("Session entry: %pI6c#%u - %pI6c#%u "
				"| %pI4#%u - %pI4#%u",
				&session->remote6.l3, session->remote6.l4,
				&session->local6.l3, session->local6.l4,
				&session->local4.l3, session->local4.l4,
				&session->remote4.l3, session->remote4.l4);
	else
		log_debug("Session entry: None");
}

///**
// * Assumes that "tuple" and "bib"'s session doesn't exist, and creates it. Returns the resulting
// * entry in "session".
// * Assumes that "tuple" represents a IPv6 packet.
// */
//static int create_session_ipv6(struct tuple *tuple6, struct bib_entry *bib,
//		struct session_entry **session, enum session_timer_type timer_type, enum tcp_state state)
//{
//	struct ipv6_prefix prefix;
//	struct in_addr ipv4_dst;
//	struct ipv4_transport_addr addr4;
//	int error;
//
//	/* Translate address from IPv6 to IPv4 */
//	error = pool6_get(&tuple6->dst.addr6.l3, &prefix);
//	if (error) {
//		log_debug("Errcode %d while obtaining %pI6c's prefix.", error, &tuple6->dst.addr6.l3);
//		return error;
//	}
//
//	error = addr_6to4(&tuple6->dst.addr6.l3, &prefix, &ipv4_dst);
//	if (error) {
//		log_debug("Error code %d while translating the packet's address.", error);
//		return error;
//	}
//
//	/*
//	 * Create the session entry.
//	 *
//	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
//	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
//	 */
//	addr4.l3 = ipv4_dst;
//	addr4.l4 = (tuple6->l4_proto != L4PROTO_ICMP) ? tuple6->dst.addr6.l4 : bib->ipv4.l4;
//
//	*session = session_create(&tuple6->src.addr6, &tuple6->dst.addr6,
//			&bib->ipv4, &addr4, tuple6->l4_proto, bib);
//	if (!(*session)) {
//		log_debug("Failed to allocate a session entry.");
//		return -ENOMEM;
//	}
//	(*session)->state = state;
//
//	apply_policies();
//
//	/* Add it to the table. */
//	error = sessiondb_add(*session, timer_type);
//	if (error) {
//		session_return(*session);
//		log_debug("Error code %d while adding the session to the DB.", error);
//		return error;
//	}
//
//	return 0;
//}
//
//static int create_session_ipv4(struct tuple *tuple4, struct bib_entry *bib,
//		struct session_entry **session)
//{
//	struct ipv6_prefix prefix;
//	struct in6_addr ipv6_src;
//	struct tuple tuple6;
//	int error;
//
//	error = pool6_peek(&prefix);
//	if (error)
//		return error;
//
//	error = addr_4to6(&tuple4->src.addr4.l3, &prefix, &ipv6_src);
//	if (error) {
//		log_debug("Error code %d while translating the packet's address.", error);
//		return error;
//	}
//
//	/*
//	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
//	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
//	 */
//	if (bib)
//		tuple6.src.addr6 = bib->ipv6;
//	else
//		memset(&tuple6.src.addr6, 0, sizeof(tuple6.src.addr6));
//	tuple6.dst.addr6.l3 = ipv6_src;
//	tuple6.dst.addr6.l4 = tuple4->src.addr4.l4;
//
//	*session = session_create(&tuple6.src.addr6, &tuple6.dst.addr6,
//			&tuple4->dst.addr4, &tuple4->src.addr4, tuple4->l4_proto, bib);
//	if (!(*session)) {
//		log_debug("Failed to allocate a session entry.");
//		return -ENOMEM;
//	}
//
//	apply_policies();
//
//	return 0;
//}

static int create_bib6(struct tuple *tuple6, struct bib_entry **result)
{
	struct ipv4_transport_addr addr4;
	struct bib_entry *bib;
	int error;

	error = palloc_allocate(tuple6, mark, &addr4);
	if (error)
		return error;
	bib = bibentry_create(&addr4, &tuple6->src.addr6, false,
			tuple6->l4_proto);
	if (!bib) {
		log_debug("Failed to allocate a BIB entry.");
		palloc_return(&addr4);
		return -ENOMEM;
	}

	return 0;
}

static int get_or_create_bib6(struct tuple *tuple6, struct bib_entry **result)
{
	struct bib_entry *bib;
	int error;

	/* TODO get or get6? */
	error = bibdb_get(tuple6, result);
	if (error != -ESRCH)
		return error; /* entry found and misc errors.*/

	/* entry not found. */
	error = create_bib6(tuple6, &bib);
	if (error)
		return error;

	/*
	 * TODO this could be better.
	 * If somebody inserted a colliding BIB since we last searched,
	 * this will fail. Instead, it should fall back to use the already
	 * official entry.
	 * Do it later though.
	 */
	error = bibdb_add(bib);
	if (error) {
		/* TODO shouldn't this happen inside kfree? */
		palloc_return(&bib->ipv4);
		bibentry_kfree(bib);
		return error;
	}

	*result = bib;
	return 0;
}

static int create_session(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **result)
{
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
		error = rfc6052_6to4(&tuple->dst.addr6.l3, &remote4.l3);
		if (error)
			return error;
		remote4.l4 = (tuple->l4_proto != L4PROTO_ICMP)
				? tuple->dst.addr6.l4
				: bib->ipv4.l4;
		break;
	case L3PROTO_IPV4:
		remote6 = bib->ipv6;
		error = rfc6052_4to6(&tuple->src.addr4.l3, &local6.l3);
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

static int get_or_create_session(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **result)
{
	struct session_entry *session;
	int error;

	error = sessiondb_get(tuple, result);
	if (error != -ESRCH)
		return error; /* entry found and misc errors.*/

	/* entry not found. */

	error = create_session(tuple, bib, &session);
	if (error)
		return error;

	error = sessiondb_add(session, true);
	if (error) {
		session_return(session);
		return error;
	}

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
static verdict ipv6_simple(struct packet *pkt, struct tuple *tuple6)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = get_or_create_bib6(tuple6, &bib);
	if (error) {
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}
	log_bib(bib);

	error = get_or_create_session(tuple6, bib, &session);
	if (error) {
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		bibdb_return(bib);
		return VERDICT_DROP;
	}
	log_session(session);

	session_return(session);
	bibdb_return(bib);

	return VERDICT_CONTINUE;
}

/**
 * Attempts to find "tuple"'s BIB entry and returns it in "bib".
 * Assumes "tuple" represents a IPv4 packet.
 */
static int get_bib4(struct packet *pkt, struct tuple *tuple4,
		struct bib_entry **bib)
{
	int error;

	error = bibdb_get(tuple4, bib);
	if (error == -ESRCH) {
		log_debug("There is no BIB entry for the IPv4 packet.");
		inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
		return error;
	} else if (error) {
		log_debug("Errcode %d while finding a BIB entry.", error);
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		icmp64_send(pkt, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	}

	if (config_get_addr_dependent_filtering() && !sessiondb_allow(tuple4)) {
		log_debug("Packet was blocked by address-dependent filtering.");
		icmp64_send(pkt, ICMPERR_FILTER, 0);
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		bibdb_return(*bib);
		return -EPERM;
	}

	return 0;
}

/**
 * Assumes that "tuple" represents a IPv4-UDP or ICMP packet, and filters and updates based on it.
 *
 * This is RFC 6146, second halves of both sections 3.5.1 and 3.5.3.
 *
 * @param[in] skb tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv4_simple(struct packet *pkt, struct tuple *tuple4)
{
	int error;
	struct bib_entry *bib;
	struct session_entry *session;

	error = get_bib4(pkt, tuple4, &bib);
	if (error == -ESRCH)
		return VERDICT_ACCEPT;
	else if (error)
		return VERDICT_DROP;
	log_bib(bib);

	error = get_or_create_session(tuple4, bib, &session);
	if (error) {
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		bibdb_return(bib);
		return VERDICT_DROP;
	}
	log_session(session);

	session_return(session);
	bibdb_return(bib);

	return VERDICT_CONTINUE;
}

/**
 * First half of the filtering and updating done during the CLOSED state of the TCP state machine.
 * Processes IPv6 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_closed_v6_syn(struct packet *pkt, struct tuple *tuple6)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = bibdb_get_or_create_ipv6(pkt, tuple6, &bib);
	if (error)
		return error;
	log_bib(bib);

	error = create_session_ipv6(tuple6, bib, &session, SESSIONTIMER_TRANS, V6_INIT);
	if (error) {
		bib_return(bib);
		return error;
	}
	log_session(session);

	session_return(session);
	bib_return(bib);

	return 0;
}

/**
 * Second half of the filtering and updating done during the CLOSED state of the TCP state machine.
 * Processes IPv4 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_v4_syn(struct packet *pkt, struct tuple *tuple4)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;
	verdict result = VERDICT_DROP;

	if (config_get_drop_external_connections()) {
		log_debug("Applying policy: Dropping externally initiated TCP connections.");
		return VERDICT_DROP;
	}

	error = bibdb_get(tuple4, &bib);
	if (error) {
		if (error != -ESRCH)
			return VERDICT_DROP;
		bib = NULL;
	}
	log_bib(bib);

	error = create_session_ipv4(tuple4, bib, &session);
	if (error)
		goto end_bib;
	log_session(session);

	session->state = V4_INIT;

	if (!bib || config_get_addr_dependent_filtering()) {
		error = pktqueue_add(session, pkt);
		if (error) {
			if (error == -E2BIG) {
				/* Fall back to assume there's no Simultaneous Open. */
				icmp64_send(pkt, ICMPERR_PORT_UNREACHABLE, 0);
			}
			goto end_session;
		}

		/* At this point, skb's original skb completely belongs to pktqueue. */
		result = VERDICT_STOLEN;

		error = sessiondb_add(session, SESSIONTIMER_SYN);
		if (error) {
			log_debug("Error code %d while adding the session to the DB.", error);
			pktqueue_remove(session);
			goto end_session;
		}

	} else {
		error = sessiondb_add(session, SESSIONTIMER_TRANS);
		if (error) {
			log_debug("Error code %d while adding the session to the DB.", error);
			goto end_session;
		}

		result = VERDICT_CONTINUE;
	}

	/* Fall through. */

end_session:
	session_return(session);
	/* Fall through. */

end_bib:
	if (bib)
		bib_return(bib);
	return result;
}

/**
 * Filtering and updating done during the CLOSED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_state_handle(struct packet *pkt, struct tuple *tuple)
{
	struct bib_entry *bib;
	verdict result;
	int error;

	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV6:
		if (pkt_tcp_hdr(pkt)->syn) {
			result = is_error(tcp_closed_v6_syn(pkt, tuple)) ? VERDICT_DROP : VERDICT_CONTINUE;
			goto syn_out;
		}
		break;

	case L3PROTO_IPV4:
		if (pkt_tcp_hdr(pkt)->syn) {
			result = tcp_closed_v4_syn(pkt, tuple);
			goto syn_out;
		}
		break;
	}

	error = bibdb_get(tuple, &bib);
	if (error) {
		log_debug("Closed state: Packet is not SYN and there is no BIB entry, so discarding. "
				"ERRcode %d", error);
		inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
		return VERDICT_DROP;
	}

	bib_return(bib);
	return VERDICT_CONTINUE;

syn_out:
	if (result == VERDICT_DROP)
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
	return result;
}

/**
 * Filtering and updating done during the V4 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_init_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_l3_proto(pkt) == L3PROTO_IPV6 && pkt_tcp_hdr(pkt)->syn) {
		*expirer = set_timer(session, &expirer_tcp_est);
		session->state = ESTABLISHED;
	} /* else, the state remains unchanged. */

	return 0;
}

/**
 * Filtering and updating done during the V6 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_init_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_tcp_hdr(pkt)->syn) {
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV4:
			*expirer = set_timer(session, &expirer_tcp_est);
			session->state = ESTABLISHED;
			break;
		case L3PROTO_IPV6:
			*expirer = set_timer(session, &expirer_tcp_trans);
			break;
		}
	} /* else, the state remains unchanged */

	return 0;
}

/**
 * Filtering and updating done during the ESTABLISHED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_established_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_tcp_hdr(pkt)->fin) {
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV4:
			session->state = V4_FIN_RCV;
			break;
		case L3PROTO_IPV6:
			session->state = V6_FIN_RCV;
			break;
		}

	} else if (pkt_tcp_hdr(pkt)->rst) {
		*expirer = set_timer(session, &expirer_tcp_trans);
		session->state = TRANS;
	} else {
		*expirer = set_timer(session, &expirer_tcp_est);
	}

	return 0;
}

/**
 * Filtering and updating done during the V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_rcv_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_l3_proto(pkt) == L3PROTO_IPV6 && pkt_tcp_hdr(pkt)->fin) {
		*expirer = set_timer(session, &expirer_tcp_trans);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		*expirer = set_timer(session, &expirer_tcp_est);
	}
	return 0;
}

/**
 * Filtering and updating done during the V6 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_fin_rcv_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_l3_proto(pkt) == L3PROTO_IPV4 && pkt_tcp_hdr(pkt)->fin) {
		*expirer = set_timer(session, &expirer_tcp_trans);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		*expirer = set_timer(session, &expirer_tcp_est);
	}
	return 0;
}

/**
 * Filtering and updating done during the V6 FIN + V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_v6_fin_rcv_state_handle(struct packet *pkt,
		struct session_entry *session)
{
	return 0; /* Only the timeout can change this state. */
}

/**
 * Filtering and updating done during the TRANS state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_trans_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (!pkt_tcp_hdr(pkt)->rst) {
		*expirer = set_timer(session, &expirer_tcp_est);
		session->state = ESTABLISHED;
	}

	return 0;
}

int sessiondb_tcp_state_machine(struct packet *pkt, struct session_entry *session)
{
	struct expire_timer *expirer = NULL;
	int error;

	spin_lock(&session_table_tcp.lock);

	switch (session->state) {
	case V4_INIT:
		error = tcp_v4_init_state_handle(pkt, session, &expirer);
		break;
	case V6_INIT:
		error = tcp_v6_init_state_handle(pkt, session, &expirer);
		break;
	case ESTABLISHED:
		error = tcp_established_state_handle(pkt, session, &expirer);
		break;
	case V4_FIN_RCV:
		error = tcp_v4_fin_rcv_state_handle(pkt, session, &expirer);
		break;
	case V6_FIN_RCV:
		error = tcp_v6_fin_rcv_state_handle(pkt, session, &expirer);
		break;
	case V4_FIN_V6_FIN_RCV:
		error = tcp_v4_fin_v6_fin_rcv_state_handle(pkt, session);
		break;
	case TRANS:
		error = tcp_trans_state_handle(pkt, session, &expirer);
		break;
	default:
		/*
		 * Because closed sessions are not supposed to be stored,
		 * CLOSED is known to fall through here.
		 */
		WARN(true, "Invalid state found: %u.", session->state);
		error = -EINVAL;
	}

	spin_unlock(&session_table_tcp.lock);

	commit_timer(expirer);

	return error;
}

/**
 * Assumes that "tuple" represents a TCP packet, and filters and updates based on it.
 * Encapsulates the TCP state machine.
 *
 * This is RFC 6146 section 3.5.2.
 */
static verdict tcp(struct packet *pkt, struct tuple *tuple)
{
	struct session_entry *session;
	int error;

	error = sessiondb_get(tuple, &session);
	if (error != 0 && error != -ESRCH) {
		log_debug("Error code %d while trying to find a TCP session.",
				error);
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}

	if (error == -ESRCH)
		return tcp_closed_state_handle(pkt, tuple);

	log_session(session);
	error = sessiondb_tcp_state_machine(pkt, session);
	session_return(session);
	if (error) {
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}
	return VERDICT_CONTINUE;
}

/**
 * filtering_and_updating - Main F&U routine. Decides if "skb" should be
 * processed, updating binding and session information.
 */
verdict filtering_and_updating(struct packet *pkt, struct tuple *in_tuple)
{
	struct ipv6hdr *hdr_ip6;
	verdict result = VERDICT_CONTINUE;

	log_debug("Step 2: Filtering and Updating");

	switch (pkt_l3_proto(pkt)) {
	case L3PROTO_IPV6:
		/* ICMP errors should not be filtered or affect the tables. */
		if (pkt_is_icmp6_error(pkt)) {
			log_debug("Packet is ICMPv6 error; skipping step...");
			return VERDICT_CONTINUE;
		}
		/* Get rid of hairpinning loops and unwanted packets. */
		hdr_ip6 = pkt_ip6_hdr(pkt);
		if (pool6_contains(&hdr_ip6->saddr)) {
			log_debug("Hairpinning loop. Dropping...");
			inc_stats(pkt, IPSTATS_MIB_INADDRERRORS);
			return VERDICT_DROP;
		}
		/*
		 * The RFC wants another pool6 validation here. I removed it
		 * because it's redundant. See core_6to4().
		 */
		break;
	case L3PROTO_IPV4:
		/* ICMP errors should not be filtered or affect the tables. */
		if (pkt_is_icmp4_error(pkt)) {
			log_debug("Packet is ICMPv4 error; skipping step...");
			return VERDICT_CONTINUE;
		}
		/*
		 * The RFC wants a pool4 validation here. I removed it because
		 * it's redundant. See core_4to6() and is_hairpin().
		 */
		break;
	}

	switch (pkt_l4_proto(pkt)) {
	case L4PROTO_UDP:
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV6:
			result = ipv6_simple(pkt, in_tuple);
			break;
		case L3PROTO_IPV4:
			result = ipv4_simple(pkt, in_tuple);
			break;
		}
		break;

	case L4PROTO_TCP:
		result = tcp(pkt, in_tuple);
		break;

	case L4PROTO_ICMP:
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV6:
			if (config_get_filter_icmpv6_info()) {
				log_debug("Packet is ICMPv6 info (ping); "
						"dropping due to policy.");
				inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
				return VERDICT_DROP;
			}

			result = ipv6_simple(pkt, in_tuple);
			break;
		case L3PROTO_IPV4:
			result = ipv4_simple(pkt, in_tuple);
			break;
		}
		break;

	case L4PROTO_OTHER:
		WARN(true, "Unknown layer 4 protocol: %d", pkt_l4_proto(pkt));
		result = VERDICT_DROP;
		break;
	}

	log_debug("Done: Step 2.");
	return result;
}
