#include "nat64/mod/filtering_and_updating.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/icmp_wrapper.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"
#include "nat64/mod/send_packet.h"

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>
#include <net/tcp.h>
#include <net/icmp.h>


/** Current valid configuration for the filtering and updating module. */
static struct filtering_config *config;

/** Sessions whose expiration date was initialized using "config".to.udp. */
static LIST_HEAD(sessions_udp);
/** Sessions whose expiration date was initialized using "config".to.tcp_est. */
static LIST_HEAD(sessions_tcp_est);
/** Sessions whose expiration date was initialized using "config".to.tcp_trans. */
static LIST_HEAD(sessions_tcp_trans);
/** Sessions whose expiration date was initialized using "config".to.icmp. */
static LIST_HEAD(sessions_icmp);
/** Sessions whose expiration date was initialized using "TCP_INCOMING_SYN". */
static LIST_HEAD(sessions_syn);

/** Deletes expired sessions every once in a while. */
static struct timer_list expire_timer;


/** The states from the TCP state machine; RFC 6146 section 3.5.2. */
enum tcp_states {
	/** No traffic has been seen; state is fictional. */
	CLOSED = 0,
	/** A SYN packet arrived from the IPv6 side; some IPv4 node is trying to start a connection. */
	V6_INIT,
	/** A SYN packet arrived from the IPv4 side; some IPv4 node is trying to start a connection. */
	V4_INIT,
	/** The handshake is complete and the sides are exchanging upper-layer data. */
	ESTABLISHED,
	/**
	 * The IPv4 node wants to terminate the connection. Data can still flow.
	 * Awaiting a IPv6 FIN...
	 */
	V4_FIN_RCV,
	/**
	 * The IPv6 node wants to terminate the connection. Data can still flow.
	 * Awaiting a IPv4 FIN...
	 */
	V6_FIN_RCV,
	/** Both sides issued a FIN. Packets can still flow for a short time. */
	V4_FIN_V6_FIN_RCV,
	/** The session might die in a short while. */
	TRANS,
};


/**
 * Helper of the set_*_timer functions. Safely updates "session"->dying_time and moves it from its
 * original location to the end of "list".
 */
static void update_timer(struct session_entry *session, struct list_head *list, __u64 ttl)
{
	session->dying_time = jiffies + ttl;

	list_del(&session->expire_list_hook);
	list_add(&session->expire_list_hook, list->prev);

	/*
	 * TODO (performance) is the second comparison really neccesary?
	 * The new session should always expire last.
	 */
	if (!timer_pending(&expire_timer) || time_before(session->dying_time, expire_timer.expires)) {
		/*
		 * We don't need to make the full "if (!timer_pending) then mod_timer" atomic because both
		 * threads are going to set the expiration at roughly the same time, so the outcome is the
		 * same.
		 */
		mod_timer(&expire_timer, session->dying_time);
		log_debug("The session cleaning timer will awake in %u msecs.",
				jiffies_to_msecs(expire_timer.expires - jiffies));
	}
}

/**
 * Marks "session" to be destroyed after the UDP session lifetime has lapsed.
 */
static void set_udp_timer(struct session_entry *session)
{
	__u64 ttl;

	rcu_read_lock_bh();
	ttl = rcu_dereference_bh(config)->to.udp;
	rcu_read_unlock_bh();

	update_timer(session, &sessions_udp, ttl);
}

/**
 * Marks "session" to be destroyed after the establised TCP session lifetime has lapsed.
 */
static void set_tcp_est_timer(struct session_entry *session)
{
	__u64 ttl;

	rcu_read_lock_bh();
	ttl = rcu_dereference_bh(config)->to.tcp_est;
	rcu_read_unlock_bh();

	update_timer(session, &sessions_tcp_est, ttl);
}

/**
 * Marks "session" to be destroyed after the transitory TCP session lifetime has lapsed.
 */
static void set_tcp_trans_timer(struct session_entry *session)
{
	__u64 ttl;

	rcu_read_lock_bh();
	ttl = rcu_dereference_bh(config)->to.tcp_trans;
	rcu_read_unlock_bh();

	update_timer(session, &sessions_tcp_trans, ttl);
}

/**
 * Marks "session" to be destroyed after the ICMP session lifetime has lapsed.
 */
static void set_icmp_timer(struct session_entry *session)
{
	__u64 ttl;

	rcu_read_lock_bh();
	ttl = rcu_dereference_bh(config)->to.icmp;
	rcu_read_unlock_bh();

	update_timer(session, &sessions_icmp, ttl);
}

/**
 * Marks "session" to be destroyed after TCP_INCOMING_SYN seconds have lapsed.
 */
/*
static void set_syn_timer(struct session_entry *session)
{
	__u64 ttl = msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
	update_timer(session, &sessions_syn, ttl);
}
*/

/**
 * Returns the earlier time between "current_min" and "list"'s first node's expiration date.
 */
static void choose_prior(struct list_head *list, unsigned long *min, bool *min_exists)
{
	struct session_entry *session;

	if (list_empty(list))
		return;

	session = list_entry(list->next, struct session_entry, expire_list_hook);

	if (*min_exists)
		*min = time_before(*min, session->dying_time) ? *min : session->dying_time;
	else
		*min = session->dying_time;
	*min_exists = true;
}

/**
 * Returns the time the next session will expire at.
 */
static unsigned long get_next_dying_time(void)
{
	unsigned long current_min = jiffies + msecs_to_jiffies(7200000);
	unsigned long absolute_min = jiffies + MIN_TIMER_SLEEP;
	bool min_exists = false;

	/* The lists are sorted by expiration date, so only each list's first entry is relevant. */
	choose_prior(&sessions_udp, &current_min, &min_exists);
	choose_prior(&sessions_tcp_est, &current_min, &min_exists);
	choose_prior(&sessions_tcp_trans, &current_min, &min_exists);
	choose_prior(&sessions_icmp, &current_min, &min_exists);
	choose_prior(&sessions_syn, &current_min, &min_exists);

	if (current_min < absolute_min)
		current_min = absolute_min;

	return current_min;
}

/**
 * Sends a probe packet to "session"'s IPv6 endpoint.
 *
 * From RFC 6146 page 30.
 *
 * @param[in] session the established session that has been inactive for too long.
 */
static void send_probe_packet(struct session_entry *session)
{
	struct sk_buff* skb;
	struct ipv6hdr *iph;
	struct tcphdr *th;
	int error;

	unsigned int l3_hdr_len = sizeof(*iph);
	unsigned int l4_hdr_len = sizeof(*th);

	skb = alloc_skb(LL_MAX_HEADER + l3_hdr_len + l4_hdr_len, GFP_ATOMIC);
	if (!skb) {
		log_warning("Could now allocate a probe packet.");
		goto fail;
	}

	skb_reserve(skb, LL_MAX_HEADER);
	skb_put(skb, l3_hdr_len + l4_hdr_len);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3_hdr_len);

	iph = ipv6_hdr(skb);
	iph->version = 6;
	iph->priority = 0;
	iph->flow_lbl[0] = 0;
	iph->flow_lbl[1] = 0;
	iph->flow_lbl[2] = 0;
	iph->payload_len = l4_hdr_len;
	iph->nexthdr = NEXTHDR_TCP;
	iph->hop_limit = 255;
	iph->saddr = session->ipv6.local.address;
	iph->daddr = session->ipv6.remote.address;

	th = tcp_hdr(skb);
	th->source = cpu_to_be16(session->ipv6.local.l4_id);
	th->dest = cpu_to_be16(session->ipv6.remote.l4_id);
	th->seq = htonl(0);
	th->ack_seq = htonl(0);
	th->res1 = 0;
	th->doff = l4_hdr_len / 4;
	th->fin = 0;
	th->syn = 0;
	th->rst = 0;
	th->psh = 0;
	th->ack = 1;
	th->urg = 0;
	th->ece = 0;
	th->cwr = 0;
	th->window = htons(8192);
	th->check = 0;
	th->urg_ptr = 0;

	th->check = csum_ipv6_magic(&iph->saddr, &iph->daddr, l4_hdr_len, IPPROTO_TCP,
			csum_partial(th, l4_hdr_len, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_set_jcb(skb, L3PROTO_IPV6, L4PROTO_TCP, th + 1, NULL);

	error = route_ipv6(skb);
	if (error)
		goto fail;

	error = ip6_local_out(skb);
	if (error) {
		log_warning("The kernel's packet dispatch function returned errcode %d.", error);
		goto fail;
	}

	return;

fail:
	log_warning("Looks like a TCP connection will break or remain idle forever somewhere...");
}

/**
 * Decides whether "session"'s expiration should cause its destruction or not. It should be called
 * when "session" expires.
 *
 * If "session" should be destroyed, it'll return true.
 * If "session" should not be destroyed, it will update its lifetime and TCP state (if applies) and
 * will return false.
 *
 * @param[in] session The entry whose lifetime just expired.
 * @return true: remove STE. false: keep STE.
 */
static bool session_expire(struct session_entry *session)
{
	switch (session->l4_proto) {
	case L4PROTO_UDP:
	case L4PROTO_ICMP:
		return true;

	case L4PROTO_TCP:
		switch (session->state) {
		case V4_INIT:
			/* TODO (Issue #58) send the stored packet. */
			/* send_icmp_error_message(skb, DESTINATION_UNREACHABLE, ADDRESS_UNREACHABLE); */
			session->state = CLOSED;
			return true;

		case ESTABLISHED:
			send_probe_packet(session);
			session->state = TRANS;
			set_tcp_trans_timer(session);
			return false;

		case V6_INIT:
		case V4_FIN_RCV:
		case V6_FIN_RCV:
		case V4_FIN_V6_FIN_RCV:
		case TRANS:
			session->state = CLOSED;
			return true;

		case CLOSED:
			/* Closed sessions are not supposed to be stored. */
			log_err(ERR_INVALID_STATE, "Closed state found; removing session entry.");
			return true;
		}

		log_err(ERR_INVALID_STATE, "Unknown state found (%d); removing session entry.",
				session->state);
		return true;

	case L4PROTO_NONE:
		log_err(ERR_L4PROTO, "Invalid transport protocol: NONE.");
		return true;
	}

	log_err(ERR_L4PROTO, "Unknown transport protocol: %u.", session->l4_proto);
	return true;
}

/**
 * Iterates through "list", deleting expired sessions.
 * "list" is assumed to be sorted by expiration date, so it will stop on the first unexpired
 * session.
 *
 * @return "true" if all sessions from the list were wiped.
 */
static bool clean_expired_sessions(struct list_head *list)
{
	struct list_head *current_hook, *next_hook;
	struct session_entry *session;
	struct bib_entry *bib;
	unsigned int s = 0;
	unsigned int b = 0;
	l4_protocol l4_proto;

	list_for_each_safe(current_hook, next_hook, list) {
		session = list_entry(current_hook, struct session_entry, expire_list_hook);

		if (time_before(jiffies, session->dying_time)) {
			log_debug("Deleted %u sessions and %u BIB entries.", s, b);
			return false;
		}
		if (!session_expire(session))
			continue; /* The entry's TTL changed, which doesn't mean the next one isn't expired. */

		if (is_error(session_remove(session)))
			continue; /* Error msg already printed. */

		bib = session->bib;
		l4_proto = session->l4_proto;

		list_del(&session->bib_list_hook);
		list_del(&session->expire_list_hook);
		session_kfree(session);
		s++;

		if (!bib) {
			log_crit(ERR_NULL, "The session entry I just removed had no BIB entry."); /* ?? */
			continue;
		}

		if (!list_empty(&bib->sessions) || bib->is_static)
			continue; /* The BIB entry needn't die; no error to report. */
		if (is_error(bib_remove(bib, l4_proto)))
			continue; /* Error msg already printed. */

		pool4_return(l4_proto, &bib->ipv4);
		bib_kfree(bib);
		b++;
	}

	log_debug("Deleted %u sessions and %u BIB entries.", s, b);

	return true;
}

/**
 * Called once in a while to kick off the scheduled expired sessions massacre.
 */
static void cleaner_timer(unsigned long param)
{
	bool clean = true;

	log_debug("===============================================");
	log_debug("Deleting expired sessions...");
	spin_lock_bh(&bib_session_lock);

	clean &= clean_expired_sessions(&sessions_udp);
	clean &= clean_expired_sessions(&sessions_tcp_est);
	clean &= clean_expired_sessions(&sessions_tcp_trans);
	clean &= clean_expired_sessions(&sessions_icmp);
	clean &= clean_expired_sessions(&sessions_syn);

	spin_unlock_bh(&bib_session_lock);
	log_debug("Session database cleaned successfully.");

	if (!clean) {
		mod_timer(&expire_timer, get_next_dying_time());
		log_debug("The timer will awake again in %u msecs.",
				jiffies_to_msecs(expire_timer.expires - jiffies));
	}
}

/**
 * Use this function to safely obtain the configuration value which dictates whether Jool should
 * drop all informational ICMP packets that are traveling from IPv6 to IPv4.
 *
 * @return whether Jool should drop all ICMPv6 info packets.
 */
static bool filter_icmpv6_info(void)
{
	bool result;

	rcu_read_lock_bh();
	result = rcu_dereference_bh(config)->drop_icmp6_info;
	rcu_read_unlock_bh();

	return result;
}

/**
 * Use this function to safely obtain the configuration value which dictates whether Jool should
 * be applying "address-dependent filtering" (Look that up in the RFC).
 *
 * @return whether Jool should apply "address-dependent filtering".
 */
static bool address_dependent_filtering(void)
{
	bool result;

	rcu_read_lock_bh();
	result = rcu_dereference_bh(config)->drop_by_addr;
	rcu_read_unlock_bh();

	return result;
}

/**
 * Use this function to safely obtain the configuration value which dictates whether IPv4 nodes
 * should be allowed to initiate conversations with IPv6 nodes.
 *
 * @return whether IPv4 nodes should be allowed to initiate conversations with IPv6 nodes.
 */
static bool drop_external_connections(void)
{
	bool result;

	rcu_read_lock_bh();
	result = rcu_dereference_bh(config)->drop_external_tcp;
	rcu_read_unlock_bh();

	return result;
}

struct iteration_args {
	struct tuple *tuple;
	struct ipv4_tuple_address *result;
};

/**
 * Evaluates "bib", and returns whether it is a perfect match to "void_args"'s tuple.
 *
 * See allocate_ipv4_transport_address().
 */
static int find_perfect_addr4(struct bib_entry *bib, void *void_args)
{
	struct iteration_args *args = void_args;
	struct ipv4_tuple_address tuple_addr;
	int error;

	tuple_addr.address = bib->ipv4.address;
	tuple_addr.l4_id = args->tuple->src.l4_id;

	error = pool4_get_match(args->tuple->l4_proto, &tuple_addr, &args->result->l4_id);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->address = bib->ipv4.address;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * Evaluates "bib", and returns whether it is an acceptable match to "void_args"'s tuple.
 *
 * See allocate_ipv4_transport_address().
 */
static int find_runnerup_addr4(struct bib_entry *bib, void *void_args)
{
	struct iteration_args *args = void_args;
	int error;

	error = pool4_get_any_port(args->tuple->l4_proto, &bib->ipv4.address, &args->result->l4_id);
	if (error)
		return 0; /* Not a satisfactory match; keep looking.*/

	args->result->address = bib->ipv4.address;
	return 1; /* Found a match; break the iteration with a no-error (but still non-zero) status. */
}

/**
 * "Allocates" from the IPv4 pool a new transport address. Attemps to make this address as similar
 * to "tuple"'s contents as possible.
 *
 * Sorry, we're using the term "allocate" because the RFC does. A more appropriate name in this
 * context would be "borrow (from the IPv4 pool)".
 *
 * RFC6146 - Sections 3.5.1.1 and 3.5.2.3.
 *
 * @param[in] base this should contain the IPv6 source address you want the IPv4 address for.
 * @param[out] result the transport address we borrowed from the pool.
 * @return true if everything went OK, false otherwise.
 */
static int allocate_ipv4_transport_address(struct tuple *base, struct ipv4_tuple_address *result)
{
	int error;
	struct iteration_args args = {
			.tuple = base,
			.result = result
	};

	/* First, try to find a perfect match (Same address and a compatible port or id). */
	error = bib_for_each_ipv6(base->l4_proto, &base->src.addr.ipv6, find_perfect_addr4, &args);
	if (error < 0)
		return error; /* Something failed, report.*/
	else if (error > 0)
		return 0; /* A match was found and "result" is already populated, so report success. */

	/*
	 * Else, iteration ended with no perfect match. Find a good match instead...
	 * (good match = same address, any port or id)
	 */
	error = bib_for_each_ipv6(base->l4_proto, &base->src.addr.ipv6, find_runnerup_addr4, &args);
	if (error < 0)
		return error;
	else if (error > 0)
		return 0;

	/* There are no good matches. Just use any available IPv4 address and hope for the best. */
	return pool4_get_any_addr(base->l4_proto, base->src.l4_id, result);
}

/**
 * Decides whether the packet should be filtered or not. Not yet implemented.
 */
static inline void apply_policies(void)
{
	/* TODO (Issue #41) decide whether resources and policy allow filtering to continue. */
}

/**
 * Assumes that "tuple" represents a IPv6 packet, and attempts to find its BIB entry, returning it
 * in "bib". If the entry doesn't exist, it is created.
 */
static int get_or_create_bib_ipv6(struct sk_buff *skb, struct tuple *tuple,
		struct bib_entry **bib)
{
	struct ipv6_tuple_address addr6;
	struct ipv4_tuple_address addr4;
	int error;

	error = bib_get(tuple, bib);

	if (!error)
		return 0; /* Yay, found. Done. */
	if (error != -ENOENT)
		return error; /* Any error other than "not found" should be considered fatal. */

	/* The entry does not exist; try to create it. */

	/* Look in the BIB tables for a previous packet from the same origin. */
	error = allocate_ipv4_transport_address(tuple, &addr4);
	if (error) {
		log_warning("Error code %d while 'allocating' an address for a BIB entry.", error);
		if (tuple->l4_proto != L4PROTO_ICMP) {
			/* I don't know why this is not supposed to happen with ICMP, but the RFC says so... */
			icmp64_send(skb, ICMPERR_ADDR_UNREACHABLE, 0);
		}
		return error;
	}

	/* Create */
	addr6.address = tuple->src.addr.ipv6;
	addr6.l4_id = tuple->src.l4_id;
	*bib = bib_create(&addr4, &addr6, false);
	if (!(*bib)) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
		return -ENOMEM;
	}

	/* Add */
	apply_policies();
	error = bib_add(*bib, tuple->l4_proto);
	if (error) {
		bib_kfree(*bib);
		log_err(ERR_ADD_BIB_FAILED, "Error code %d while adding a BIB entry to the DB.", error);
		return error;
	}

	return 0;
}

/**
 * Assumes that "tuple" represents a IPv4 packet, and attempts to find its BIB entry, returning it
 * in "bib". If the entry doesn't exist, it is created.
 */
static int get_or_create_bib_ipv4(struct sk_buff *skb, struct tuple *tuple,
		struct bib_entry **bib)
{
	int error;

	error = bib_get(tuple, bib);
	if (error == -ENOENT) {
		log_info("There is no BIB entry for the incoming IPv4 packet.");
		icmp64_send(skb, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	} else if (error) {
		log_warning("Error code %d while finding a BIB entry for the incoming packet.", error);
		icmp64_send(skb, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	}

	if (address_dependent_filtering() && !session_allow(tuple)) {
		log_info("Packet was blocked by address-dependent filtering.");
		icmp64_send(skb, ICMPERR_FILTER, 0);
		return -EPERM;
	}

	return 0;
}

/**
 * Assumes that "tuple" and "bib"'s session doesn't exist, and creates it. Returns the resulting
 * entry in "session".
 * Assumes that "tuple" represents a IPv6 packet.
 */
static int create_session_ipv6(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in_addr ipv4_dst;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	int error;

	/* Translate address from IPv6 to IPv4 */
	error = pool6_get(&tuple->dst.addr.ipv6, &prefix);
	if (error) {
		log_warning("Errcode %d while obtaining %pI6c's prefix.", error, &tuple->dst.addr.ipv6);
		return error;
	}

	error = addr_6to4(&tuple->dst.addr.ipv6, &prefix, &ipv4_dst);
	if (error) {
		log_err(ERR_EXTRACT_FAILED, "Error code %d while translating the packet's address.", error);
		return error;
	}

	/*
	 * Create the session entry.
	 *
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	pair6.remote.address = tuple->src.addr.ipv6;
	pair6.remote.l4_id = tuple->src.l4_id;
	pair6.local.address = tuple->dst.addr.ipv6;
	pair6.local.l4_id = tuple->dst.l4_id;
	pair4.local = bib->ipv4;
	pair4.remote.address = ipv4_dst;
	pair4.remote.l4_id = (tuple->l4_proto != L4PROTO_ICMP) ? tuple->dst.l4_id : bib->ipv4.l4_id;

	*session = session_create(&pair4, &pair6, tuple->l4_proto);
	if (!(*session)) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
		return -ENOMEM;
	}

	apply_policies();

	/* Add it to the table. */
	error = session_add(*session);
	if (error) {
		session_kfree(*session);
		log_err(ERR_ADD_SESSION_FAILED, "Error code %d while adding the session to the DB.", error);
		return error;
	}

	/* Cross-reference the entry with its BIB. */
	(*session)->bib = bib;
	list_add(&(*session)->bib_list_hook, &bib->sessions);

	return 0;
}

/**
 * Assumes that "tuple" and "bib" represent a IPv6 packet, and attempts to find their session entry,
 * returning it in "session". If the entry doesn't exist, it is created.
 */
static int get_or_create_session_ipv6(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	int error;

	error = session_get(tuple, session);
	if (!error)
		return 0; /* Yay, found. Done. */
	if (error != -ENOENT)
		return error; /* Any error other than "not found" should be considered fatal. */

	/* The entry does not exist; try to create it. */
	return create_session_ipv6(tuple, bib, session);
}

/**
 * Assumes that "tuple" and "bib"'s session doesn't exist, and creates it. Returns the resulting
 * entry in "session".
 * Assumes that "tuple" represents a IPv4 packet.
 */
static int create_session_ipv4(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in6_addr ipv6_src;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	int error;

	/* Translate address from IPv4 to IPv6 */
	error = pool6_peek(&prefix);
	if (error)
		return error;

	error = addr_4to6(&tuple->src.addr.ipv4, &prefix, &ipv6_src);
	if (error) {
		log_err(ERR_APPEND_FAILED, "Error code %d while translating the packet's address.", error);
		return error;
	}

	/*
	 * Create the session entry.
	 *
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	pair6.remote = bib->ipv6;
	pair6.local.address = ipv6_src;
	pair6.local.l4_id = (tuple->l4_proto != L4PROTO_ICMP) ? tuple->src.l4_id : bib->ipv6.l4_id;
	pair4.local.address = tuple->dst.addr.ipv4;
	pair4.local.l4_id = tuple->dst.l4_id;
	pair4.remote.address = tuple->src.addr.ipv4;
	pair4.remote.l4_id = tuple->src.l4_id;

	*session = session_create(&pair4, &pair6, tuple->l4_proto);
	if (!(*session)) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
		return -ENOMEM;
	}

	apply_policies();

	/* Add it to the table. */
	error = session_add(*session);
	if (error) {
		session_kfree(*session);
		log_err(ERR_ADD_SESSION_FAILED, "Error code %d while adding the session to the DB.", error);
		return error;
	}

	/* Cross-reference the entry with its BIB. */
	(*session)->bib = bib;
	list_add(&(*session)->bib_list_hook, &bib->sessions);

	return 0;
}

/**
 * Assumes that "tuple" and "bib" represent a IPv4 packet, and attempts to find their session entry,
 * returning it in "session". If the entry doesn't exist, it is created.
 */
static int get_or_create_session_ipv4(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	int error;

	error = session_get(tuple, session);
	if (!error)
		return 0; /* Yay, found. Done. */
	if (error != -ENOENT)
		return error; /* Any error other than "not found" should be considered fatal. */

	/* The entry does not exist; try to create it. */
	return create_session_ipv4(tuple, bib, session);
}

/**
 * Assumes that "tuple" represents a IPv6-UDP packet, and filters and updates based on it.
 *
 * This is RFC 6146 section 3.5.1, first half.
 *
 * @param[in] skb tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv6_udp(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = get_or_create_bib_ipv6(skb, tuple, &bib);
	if (error)
		return VER_DROP;

	error = get_or_create_session_ipv6(tuple, bib, &session);
	if (error) {
		bib_remove(bib, tuple->l4_proto);
		pool4_return(tuple->l4_proto, &bib->ipv4);
		bib_kfree(bib);
		return VER_DROP;
	}

	set_udp_timer(session);

	return VER_CONTINUE;
}

/**
 * Assumes that "tuple" represents a IPv4-UDP packet, and filters and updates based on it.
 *
 * This is RFC 6146 section 3.5.1, second half.
 *
 * @param[in] skb tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv4_udp(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;

	if (is_error(get_or_create_bib_ipv4(skb, tuple, &bib)))
		return VER_DROP;
	if (is_error(get_or_create_session_ipv4(tuple, bib, &session)))
		return VER_DROP;

	set_udp_timer(session);

	return VER_CONTINUE;
}

/**
 * Assumes that "tuple" represents a IPv6-ICMP packet, and filters and updates based on it.
 *
 * This is RFC 6146 section 3.5.3, first half.
 *
 * @param[in] skb tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv6_icmp6(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	if (filter_icmpv6_info()) {
		log_info("Packet is ICMPv6 info (ping); dropping due to policy.");
		return VER_DROP;
	}

	error = get_or_create_bib_ipv6(skb, tuple, &bib);
	if (error)
		return VER_DROP;

	error = get_or_create_session_ipv6(tuple, bib, &session);
	if (error) {
		bib_remove(bib, tuple->l4_proto);
		pool4_return(tuple->l4_proto, &bib->ipv4);
		bib_kfree(bib);
		return VER_DROP;
	}

	set_icmp_timer(session);

	return VER_CONTINUE;
}

/**
 * Assumes that "tuple" represents a IPv4-ICMP packet, and filters and updates based on it.
 *
 * This is RFC 6146 section 3.5.3, second half.
 *
 * @param[in] skb tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv4_icmp4(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;

	if (is_error(get_or_create_bib_ipv4(skb, tuple, &bib)))
		return VER_DROP;
	if (is_error(get_or_create_session_ipv4(tuple, bib, &session)))
		return VER_DROP;

	set_icmp_timer(session);

	return VER_CONTINUE;
}

/**
 * First half of the filtering and updating done during the CLOSED state of the TCP state machine.
 * Processes IPv6 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_closed_v6_syn(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = get_or_create_bib_ipv6(skb, tuple, &bib);
	if (error)
		return error;

	error = create_session_ipv6(tuple, bib, &session);
	if (error) {
		bib_remove(bib, tuple->l4_proto);
		pool4_return(tuple->l4_proto, &bib->ipv4);
		bib_kfree(bib);
		return error;
	}

	set_tcp_trans_timer(session);
	session->state = V6_INIT;

	return 0;
}

static inline void store_packet(void)
{
	/* TODO (Issue #58) store the packet. */
	log_warning("Unknown TCP connections started from the IPv4 side are still unsupported. "
			"Dropping packet...");
}

/**
 * Second half of the filtering and updating done during the CLOSED state of the TCP state machine.
 * Processes IPv4 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_closed_v4_syn(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	if (drop_external_connections()) {
		log_info("Applying policy: Dropping externally initiated TCP connections.");
		return -EPERM;
	}

	if (address_dependent_filtering()) {
		/* TODO (issue #58) set_syn_timer(session); */
		log_warning("Storage of TCP packets is not yet supported.");
		return -EINVAL;
	}

	error = bib_get(tuple, &bib);
	if (error) {
		if (error == -ENOENT)
			store_packet();
		return error;
	}

	error = create_session_ipv4(tuple, bib, &session);
	if (error)
		return error;

	session->state = V4_INIT;
	set_tcp_trans_timer(session);

	return 0;
}

/**
 * Filtering and updating done during the CLOSED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_closed_state_handle(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	int error;

	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV6:
		if (tcp_hdr(skb)->syn)
			return tcp_closed_v6_syn(skb, tuple);
		break;

	case L3PROTO_IPV4:
		if (tcp_hdr(skb)->syn)
			return tcp_closed_v4_syn(skb, tuple);
		break;
	}

	error = bib_get(tuple, &bib);
	if (error) {
		log_info("Closed state: Packet is not SYN and there is no BIB, so discarding. ERRcode %d",
				error);
	}

	return error;
}

/**
 * Filtering and updating done during the V4 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_init_state_handle(struct sk_buff *skb, struct session_entry *session)
{
	if (skb_l3_proto(skb) == L3PROTO_IPV6 && tcp_hdr(skb)->syn) {
		set_tcp_est_timer(session);
		session->state = ESTABLISHED;
	} /* else, the state remains unchanged. */

	return 0;
}

/**
 * Filtering and updating done during the V6 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_init_state_handle(struct sk_buff *skb, struct session_entry *session)
{
	if (tcp_hdr(skb)->syn) {
		switch (skb_l3_proto(skb)) {
		case L3PROTO_IPV4:
			set_tcp_est_timer(session);
			session->state = ESTABLISHED;
			break;
		case L3PROTO_IPV6:
			set_tcp_trans_timer(session);
			break;
		}
	} /* else, the state remains unchanged */

	return 0;
}

/**
 * Filtering and updating done during the ESTABLISHED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_established_state_handle(struct sk_buff *skb, struct session_entry *session)
{
	if (tcp_hdr(skb)->fin) {
		switch (skb_l3_proto(skb)) {
		case L3PROTO_IPV4:
			session->state = V4_FIN_RCV;
			break;
		case L3PROTO_IPV6:
			session->state = V6_FIN_RCV;
			break;
		}

	} else if (tcp_hdr(skb)->rst) {
		set_tcp_trans_timer(session);
		session->state = TRANS;
	} else {
		set_tcp_est_timer(session);
	}

	return 0;
}

/**
 * Filtering and updating done during the V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_rcv_state_handle(struct sk_buff *skb, struct session_entry *session)
{
	if (skb_l3_proto(skb) == L3PROTO_IPV6 && tcp_hdr(skb)->fin) {
		set_tcp_trans_timer(session);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		set_tcp_est_timer(session);
	}
	return 0;
}

/**
 * Filtering and updating done during the V6 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_fin_rcv_state_handle(struct sk_buff *skb, struct session_entry *session)
{
	if (skb_l3_proto(skb) == L3PROTO_IPV4 && tcp_hdr(skb)->fin) {
		set_tcp_trans_timer(session);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		set_tcp_est_timer(session);
	}
	return 0;
}

/**
 * Filtering and updating done during the V6 FIN + V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_v6_fin_rcv_state_handle(struct sk_buff *skb,
		struct session_entry *session)
{
	return 0; /* Only the timeout can change this state. */
}

/**
 * Filtering and updating done during the TRANS state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_trans_state_handle(struct sk_buff *skb, struct session_entry *session)
{
	if (!tcp_hdr(skb)->rst) {
		set_tcp_est_timer(session);
		session->state = ESTABLISHED;
	}

	return 0;
}

/**
 * Assumes that "tuple" represents a TCP packet, and filters and updates based on it.
 * Encapsulates the TCP state machine.
 *
 * This is RFC 6146 section 3.5.2.
 */
static verdict tcp(struct sk_buff *skb, struct tuple *tuple)
{
	struct session_entry *session;
	int error;

	error = session_get(tuple, &session);
	if (error != 0 && error != -ENOENT) {
		log_warning("Error code %d while trying to find a TCP session.", error);
		goto end;
	}

	/* If NO session was found: */
	if (error == -ENOENT) {
		error = tcp_closed_state_handle(skb, tuple);
		goto end;
	}

	/* Act according the current state. */
	switch (session->state) {
	case V4_INIT:
		error = tcp_v4_init_state_handle(skb, session);
		break;
	case V6_INIT:
		error = tcp_v6_init_state_handle(skb, session);
		break;
	case ESTABLISHED:
		error = tcp_established_state_handle(skb, session);
		break;
	case V4_FIN_RCV:
		error = tcp_v4_fin_rcv_state_handle(skb, session);
		break;
	case V6_FIN_RCV:
		error = tcp_v6_fin_rcv_state_handle(skb, session);
		break;
	case V4_FIN_V6_FIN_RCV:
		error = tcp_v4_fin_v6_fin_rcv_state_handle(skb, session);
		break;
	case TRANS:
		error = tcp_trans_state_handle(skb, session);
		break;
	default:
		/*
		 * Because closed sessions are not supposed to be stored,
		 * CLOSED is known to fall through here.
		 */
		log_err(ERR_INVALID_STATE, "Invalid state found: %u.", session->state);
		error = -EINVAL;
	}
	/* Fall through. */

end:
	return error ? VER_DROP : VER_CONTINUE;
}

/**
 * Prepares this module for future use. Avoid calling the rest of the functions unless this has
 * already been executed once.
 *
 * @return zero on success, nonzero on failure.
 */
int filtering_init(void)
{
	config = kmalloc(sizeof(*config), GFP_ATOMIC);
	if (!config) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate memory to store the filtering config.");
		return -ENOMEM;
	}

	config->to.udp = msecs_to_jiffies(1000 * UDP_DEFAULT);
	config->to.icmp = msecs_to_jiffies(1000 * ICMP_DEFAULT);
	config->to.tcp_trans = msecs_to_jiffies(1000 * TCP_TRANS);
	config->to.tcp_est = msecs_to_jiffies(1000 * TCP_EST);
	config->drop_by_addr = FILT_DEF_ADDR_DEPENDENT_FILTERING;
	config->drop_external_tcp = FILT_DEF_DROP_EXTERNAL_CONNECTIONS;
	config->drop_icmp6_info = FILT_DEF_FILTER_ICMPV6_INFO;

	INIT_LIST_HEAD(&sessions_udp);
	INIT_LIST_HEAD(&sessions_tcp_est);
	INIT_LIST_HEAD(&sessions_tcp_trans);
	INIT_LIST_HEAD(&sessions_icmp);
	INIT_LIST_HEAD(&sessions_syn);

	init_timer(&expire_timer);
	expire_timer.function = cleaner_timer;
	expire_timer.expires = 0;
	expire_timer.data = 0;

	return 0;
}

/**
 * Frees any memory allocated by this module.
 */
void filtering_destroy(void)
{
	del_timer_sync(&expire_timer);
	kfree(config);
}

/**
 * Copies this module's current configuration to "clone".
 *
 * @param[out] clone a copy of the current config will be placed here. Must be already allocated.
 * @return zero on success, nonzero on failure.
 */
int clone_filtering_config(struct filtering_config *clone)
{
	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	rcu_read_unlock_bh();
	return 0;
}

/**
 * Updates the configuration of this module.
 *
 * @param[in] operation indicator of which fields from "new_config" should be taken into account.
 * @param[in] new configuration values.
 * @return zero on success, nonzero on failure.
 */
int set_filtering_config(__u32 operation, struct filtering_config *new_config)
{
	struct filtering_config *tmp_config;
	struct filtering_config *old_config;
	int udp_min = msecs_to_jiffies(1000 * UDP_MIN);
	int tcp_est = msecs_to_jiffies(1000 * TCP_EST);
	int tcp_trans = msecs_to_jiffies(1000 * TCP_TRANS);

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	if (operation & DROP_BY_ADDR_MASK)
		tmp_config->drop_by_addr = new_config->drop_by_addr;
	if (operation & DROP_ICMP6_INFO_MASK)
		tmp_config->drop_icmp6_info = new_config->drop_icmp6_info;
	if (operation & DROP_EXTERNAL_TCP_MASK)
		tmp_config->drop_external_tcp = new_config->drop_external_tcp;

	if (operation & UDP_TIMEOUT_MASK) {
		if (new_config->to.udp < udp_min) {
			log_err(ERR_UDP_TO_RANGE, "The UDP timeout must be at least %u seconds.", UDP_MIN);
			goto fail;
		}
		tmp_config->to.udp = new_config->to.udp;
	}

	if (operation & ICMP_TIMEOUT_MASK)
		tmp_config->to.icmp = new_config->to.icmp;

	if (operation & TCP_EST_TIMEOUT_MASK) {
		if (new_config->to.tcp_est < tcp_est) {
			log_err(ERR_TCPEST_TO_RANGE, "The TCP est timeout must be at least %u seconds.",
					TCP_EST);
			goto fail;
		}
		tmp_config->to.tcp_est = new_config->to.tcp_est;
	}

	if (operation & TCP_TRANS_TIMEOUT_MASK) {
		if (new_config->to.tcp_trans < tcp_trans) {
			log_err(ERR_TCPTRANS_TO_RANGE, "The TCP trans timeout must be at least %u seconds.",
					TCP_TRANS);
			goto fail;
		}
		tmp_config->to.tcp_trans = new_config->to.tcp_trans;
	}

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();
	kfree(old_config);

	return 0;

fail:
	kfree(tmp_config);
	return -EINVAL;
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
verdict filtering_and_updating(struct sk_buff* skb, struct tuple *tuple)
{
	struct in_addr addr4;
	struct ipv6hdr *hdr_ip6;
	struct icmp6hdr *hdr_icmp6;
	struct icmphdr *hdr_icmp4;
	verdict result = VER_CONTINUE;

	log_debug("Step 2: Filtering and Updating");

	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV6:
		hdr_icmp6 = icmp6_hdr(skb);
		/* ICMP errors should not affect the tables. */
		if (skb_l4_proto(skb) == L4PROTO_ICMP && is_icmp6_error(hdr_icmp6->icmp6_type)) {
			log_debug("Packet is ICMPv6 error; skipping step...");
			return VER_CONTINUE;
		}
		/* Get rid of hairpinning loops and unwanted packets. */
		hdr_ip6 = ipv6_hdr(skb);
		if (pool6_contains(&hdr_ip6->saddr)) {
			log_info("Hairpinning loop. Dropping...");
			return VER_DROP;
		}
		if (!pool6_contains(&hdr_ip6->daddr)) {
			log_info("Packet was rejected by pool6, dropping...");
			return VER_DROP;
		}
		break;
	case L3PROTO_IPV4:
		hdr_icmp4 = icmp_hdr(skb);
		/* ICMP errors should not affect the tables. */
		if (skb_l4_proto(skb) == L4PROTO_ICMP && is_icmp4_error(hdr_icmp4->type)) {
			log_debug("Packet is ICMPv4 error; skipping step...");
			return VER_CONTINUE;
		}
		/* Get rid of unexpected packets */
		addr4.s_addr = ip_hdr(skb)->daddr;
		if (!pool4_contains(&addr4)) {
			log_info("Packet was rejected by pool4, dropping...");
			return VER_DROP;
		}
		break;
	}

	/* Process packet, according to its protocol. */
	spin_lock_bh(&bib_session_lock);

	switch (skb_l4_proto(skb)) {
	case L4PROTO_UDP:
		switch (skb_l3_proto(skb)) {
		case L3PROTO_IPV6:
			result = ipv6_udp(skb, tuple);
			break;
		case L3PROTO_IPV4:
			result = ipv4_udp(skb, tuple);
			break;
		}
		break;

	case L4PROTO_TCP:
		result = tcp(skb, tuple);
		break;

	case L4PROTO_ICMP:
		switch (skb_l3_proto(skb)) {
		case L3PROTO_IPV6:
			result = ipv6_icmp6(skb, tuple);
			break;
		case L3PROTO_IPV4:
			result = ipv4_icmp4(skb, tuple);
			break;
		}
		break;

	case L4PROTO_NONE:
		log_err(ERR_ILLEGAL_NONE, "Tuples should not contain the 'NONE' transport protocol.");
		result = VER_DROP;
		break;
	}

	spin_unlock_bh(&bib_session_lock);

	log_debug("Done: Step 2.");
	return result;
}
