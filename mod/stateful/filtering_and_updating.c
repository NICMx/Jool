#include "nat64/mod/stateful/filtering_and_updating.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/stateful/bib_db.h"
#include "nat64/mod/stateful/pkt_queue.h"
#include "nat64/mod/stateful/pool4.h"
#include "nat64/mod/stateful/session_db.h"

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
		log_debug("Session entry: %pI6c#%u - %pI6c#%u | %pI4#%u - %pI4#%u",
				&session->remote6.l3, session->remote6.l4,
				&session->local6.l3, session->local6.l4,
				&session->local4.l3, session->local4.l4,
				&session->remote4.l3, session->remote4.l4);
	else
		log_debug("Session entry: None");
}

/**
 * Attempts to find "tuple"'s BIB entry and returns it in "bib".
 * Assumes "tuple" represents a IPv4 packet.
 */
static int get_bib_ipv4(struct packet *pkt, struct tuple *tuple4, struct bib_entry **bib)
{
	int error;

	error = bibdb_get(tuple4, bib);
	if (error) {
		if (error == -ENOENT) {
			log_debug("There is no BIB entry for the incoming IPv4 packet.");
			inc_stats(pkt, IPSTATS_MIB_INNOROUTES);
		} else {
			log_debug("Error code %d while finding a BIB entry for the incoming packet.", error);
			inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
			icmp64_send(pkt, ICMPERR_ADDR_UNREACHABLE, 0);
		}
		return error;
	}

	if (config_get_addr_dependent_filtering() && !sessiondb_allow(tuple4)) {
		log_debug("Packet was blocked by address-dependent filtering.");
		icmp64_send(pkt, ICMPERR_FILTER, 0);
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		bib_return(*bib);
		return -EPERM;
	}

	return 0;
}

/**
 * Assumes that "tuple" and "bib"'s session doesn't exist, and creates it. Returns the resulting
 * entry in "session".
 * Assumes that "tuple" represents a IPv6 packet.
 */
static int create_session_ipv6(struct tuple *tuple6, struct bib_entry *bib,
		struct session_entry **session, enum session_timer_type timer_type, enum tcp_state state)
{
	struct ipv6_prefix prefix;
	struct in_addr ipv4_dst;
	struct ipv4_transport_addr addr4;
	int error;

	/* Translate address from IPv6 to IPv4 */
	error = pool6_get(&tuple6->dst.addr6.l3, &prefix);
	if (error) {
		log_debug("Errcode %d while obtaining %pI6c's prefix.", error, &tuple6->dst.addr6.l3);
		return error;
	}

	error = addr_6to4(&tuple6->dst.addr6.l3, &prefix, &ipv4_dst);
	if (error) {
		log_debug("Error code %d while translating the packet's address.", error);
		return error;
	}

	/*
	 * Create the session entry.
	 *
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	addr4.l3 = ipv4_dst;
	addr4.l4 = (tuple6->l4_proto != L4PROTO_ICMP) ? tuple6->dst.addr6.l4 : bib->ipv4.l4;

	*session = session_create(&tuple6->src.addr6, &tuple6->dst.addr6,
			&bib->ipv4, &addr4, tuple6->l4_proto, bib);
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		return -ENOMEM;
	}
	(*session)->state = state;

	apply_policies();

	/* Add it to the table. */
	error = sessiondb_add(*session, timer_type);
	if (error) {
		session_return(*session);
		log_debug("Error code %d while adding the session to the DB.", error);
		return error;
	}

	return 0;
}

static int create_session_ipv4(struct tuple *tuple4, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in6_addr ipv6_src;
	struct tuple tuple6;
	int error;

	error = pool6_peek(&prefix);
	if (error)
		return error;

	error = addr_4to6(&tuple4->src.addr4.l3, &prefix, &ipv6_src);
	if (error) {
		log_debug("Error code %d while translating the packet's address.", error);
		return error;
	}

	/*
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	if (bib)
		tuple6.src.addr6 = bib->ipv6;
	else
		memset(&tuple6.src.addr6, 0, sizeof(tuple6.src.addr6));
	tuple6.dst.addr6.l3 = ipv6_src;
	tuple6.dst.addr6.l4 = tuple4->src.addr4.l4;

	*session = session_create(&tuple6.src.addr6, &tuple6.dst.addr6,
			&tuple4->dst.addr4, &tuple4->src.addr4, tuple4->l4_proto, bib);
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		return -ENOMEM;
	}

	apply_policies();

	return 0;
}

/**
 * Assumes that "tuple" represents a IPv6-UDP or ICMP packet, and filters and updates based on it.
 *
 * This is RFC 6146, first halves of both sections 3.5.1 and 3.5.3.
 *
 * @param[in] skb tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv6_simple(struct packet *pkt, struct tuple *tuple6)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = bibdb_get_or_create_ipv6(pkt, tuple6, &bib);
	if (error) {
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}
	log_bib(bib);

	error = sessiondb_get_or_create_ipv6(tuple6, bib, &session);
	if (error) {
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		bib_return(bib);
		return VERDICT_DROP;
	}
	log_session(session);

	session_return(session);
	bib_return(bib);

	return VERDICT_CONTINUE;
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

	error = get_bib_ipv4(pkt, tuple4, &bib);
	if (error == -ENOENT)
		return VERDICT_ACCEPT;
	else if (error)
		return VERDICT_DROP;
	log_bib(bib);

	error = sessiondb_get_or_create_ipv4(tuple4, bib, &session);
	if (error) {
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		bib_return(bib);
		return VERDICT_DROP;
	}
	log_session(session);

	session_return(session);
	bib_return(bib);

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
		if (error != -ENOENT)
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
	if (error != 0 && error != -ENOENT) {
		log_debug("Error code %d while trying to find a TCP session.", error);
		inc_stats(pkt, IPSTATS_MIB_INDISCARDS);
		return VERDICT_DROP;
	}

	if (error == -ENOENT)
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
 * Main F&U routine. Called during the processing of every packet.
 *
 * Decides if "skb" should be processed, updating binding and session information.
 *
 * @param[in] skb packet being translated.
 * @param[in] tuple skb's summary.
 * @return indicator of what should happen to skb.
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
		if (!pool6_contains(&hdr_ip6->daddr)) {
			log_debug("Packet was rejected by pool6; dropping...");
			inc_stats(pkt, IPSTATS_MIB_INADDRERRORS);
			return VERDICT_DROP;
		}
		break;
	case L3PROTO_IPV4:
		/* ICMP errors should not be filtered or affect the tables. */
		if (pkt_is_icmp4_error(pkt)) {
			log_debug("Packet is ICMPv4 error; skipping step...");
			return VERDICT_CONTINUE;
		}
		/* Get rid of unexpected packets */
		if (!pool4_contains(pkt_ip4_hdr(pkt)->daddr)) {
			log_debug("Packet was rejected by pool4; dropping...");
			inc_stats(pkt, IPSTATS_MIB_INADDRERRORS);
			return VERDICT_DROP;
		}
		break;
	}

	/* Process packet, according to its protocol. */

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
				log_debug("Packet is ICMPv6 info (ping); dropping due to policy.");
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
		WARN(true, "Unknown layer 4 protocol (%d)...", pkt_l4_proto(pkt));
		break;
	}

	log_debug("Done: Step 2.");
	return result;
}
