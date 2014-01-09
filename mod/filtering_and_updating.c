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
static struct filtering_config config;
/** Synchronizes access to the "config" variable. */
static DEFINE_SPINLOCK(config_lock);

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
static void update_timer(struct session_entry *session, struct list_head *list, __u64 *ttl)
{
	spin_lock_bh(&config_lock);
	session->dying_time = jiffies + *ttl;
	spin_unlock_bh(&config_lock);

	list_del(&session->expire_list_hook);
	list_add(&session->expire_list_hook, list->prev);

	if (!timer_pending(&expire_timer) || time_before(session->dying_time, expire_timer.expires)) {
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
	update_timer(session, &sessions_udp, &config.to.udp);
}

/**
 * Marks "session" to be destroyed after the establised TCP session lifetime has lapsed.
 */
static void set_tcp_est_timer(struct session_entry *session)
{
	update_timer(session, &sessions_tcp_est, &config.to.tcp_est);
}

/**
 * Marks "session" to be destroyed after the transitory TCP session lifetime has lapsed.
 */
static void set_tcp_trans_timer(struct session_entry *session)
{
	update_timer(session, &sessions_tcp_trans, &config.to.tcp_trans);
}

/**
 * Marks "session" to be destroyed after the ICMP session lifetime has lapsed.
 */
static void set_icmp_timer(struct session_entry *session)
{
	update_timer(session, &sessions_icmp, &config.to.icmp);
}

/**
 * Marks "session" to be destroyed after TCP_INCOMING_SYN seconds have lapsed.
 */
static void set_syn_timer(struct session_entry *session)
{
	__u64 ttl = msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
	update_timer(session, &sessions_syn, &ttl);
}

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
	unsigned long current_min = 0;
	bool min_exists = false;

	/* The lists are sorted by expiration date, so only each list's first entry is relevant. */
	choose_prior(&sessions_udp, &current_min, &min_exists);
	choose_prior(&sessions_tcp_est, &current_min, &min_exists);
	choose_prior(&sessions_tcp_trans, &current_min, &min_exists);
	choose_prior(&sessions_icmp, &current_min, &min_exists);
	choose_prior(&sessions_syn, &current_min, &min_exists);

	return current_min;
}

/**
 * Sends a probe packet to "session"'s IPv6 endpoint.
 *
 * From RFC 6146 page 30.
 *
 * @param[in] session the established session that has been inactive for too long.
 * @return true if the packet could be sent, false otherwise.
 */
static bool send_probe_packet(struct session_entry *session)
{
	struct tcphdr *th;
	struct ipv6hdr *iph;
	struct sk_buff* skb;
	struct dst_entry *dst;
	int error;

	unsigned int l3_hdr_len = sizeof(*iph);
	unsigned int l4_hdr_len = sizeof(*th);

	skb = alloc_skb(LL_MAX_HEADER + l3_hdr_len + l4_hdr_len, GFP_ATOMIC);
	if (!skb)
		return false;

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

	dst = route_ipv6(iph, th, L4PROTO_TCP, 0);
	if (!dst)
		return false;
	skb->dev = dst->dev;
	skb_dst_set(skb, dst);

	error = ip6_local_out(skb);
	if (error) {
		log_err(ERR_SEND_FAILED, "The kernel's packet dispatch function returned errcode %d. "
							"Cannot send packet.", error);
		return false;
	}

	return true;
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
		/* Fall through. */
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

		if (!session_remove(session))
			continue; /* Error msg already printed. */

		bib = session->bib;
		l4_proto = session->l4_proto;

		list_del(&session->bib_list_hook);
		list_del(&session->expire_list_hook);
		session_dealloc(session);
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
		bib_dealloc(bib);
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

	spin_lock_bh(&config_lock);
	result = config.drop_icmp6_info;
	spin_unlock_bh(&config_lock);

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

	spin_lock_bh(&config_lock);
	result = config.drop_by_addr;
	spin_unlock_bh(&config_lock);

	return result;
}

/**
 * Use this function to safaly obtain the configuration value which dictates whether IPv4 nodes
 * should be allowed to initiate conversations with IPv6 nodes.
 *
 * @return whether IPv4 nodes should be allowed to initiate conversations with IPv6 nodes.
 */
static bool drop_external_connections(void)
{
	bool result;

	spin_lock_bh(&config_lock);
	result = config.drop_external_tcp;
	spin_unlock_bh(&config_lock);

	return result;
}

struct iteration_args {
	struct tuple *tuple;
	struct ipv4_tuple_address *result;
};

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

	/* First, try to find a perfect match.*/
	error = bib_for_each_ipv6(base->l4_proto, &base->src.addr.ipv6, find_perfect_addr4, &args);
	if (error < 0)
		return error; /* Something failed, report.*/
	else if (error > 0)
		return 0; /* A match was found and "result" is already populated, so report success. */
log_debug("	no perfect match.");
	/* Else, iteration ended with no perfect match. Find a good match instead... */
	error = bib_for_each_ipv6(base->l4_proto, &base->src.addr.ipv6, find_runnerup_addr4, &args);
	if (error < 0)
		return error;
	else if (error > 0)
		return 0;
log_debug("	no runnerup match.");
	/* There are no good matches. Just use any available IPv4 address and hope for the best. */

	error = pool4_get_any_addr(base->l4_proto, base->src.l4_id, result);
if (error) log_debug("	no match");
	return error;
}

/**
 * Wrapper for the 6to4 function of the rfc6052 module. Extracts the prefix from "src" and returns
 * the result as a IPv4 address on "dst".
 *
 * FIXME (error) if the user configures several prefixes w/different lengths, this is going to do
 * something weird.
 *
 * @param[in] src IPv6 address you want to translate to IPv4.
 * @param[out] dst IPv4 version of "src".
 * @return true on success, false on failure.
 */
static bool extract_ipv4(struct in6_addr *src, struct in_addr *dst)
{
	struct ipv6_prefix prefix;
	if (!pool6_peek(&prefix))
		return false;

	return addr_6to4(src, &prefix, dst);
}

/**
 * Wrapper for the 4to6 function of the rfc6052 module. Adds any known prefix to "src" and returns
 * the result as a IPv6 address on "dst".
 *
 * @param[in] src IPv6 address you want to translate to IPv6.
 * @param[out] dst IPv6 version of "src".
 * @return true on success, false on failure.
 */
static bool append_ipv4(struct in_addr *src, struct in6_addr *dst)
{
	struct ipv6_prefix prefix;
	if (!pool6_peek(&prefix))
		return false;

	return addr_4to6(src, &prefix, dst);
}

/**
 * Decides whether the packet should be filtered or not. Not yet implemented.
 */
static inline void apply_policies(void)
{
	/* TODO (Issue #41) decide whether resources and policy allow filtering to continue. */
}

static int get_or_create_bib_ipv6(struct tuple *tuple, struct bib_entry **bib)
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
		return error;
	}

	/* Create */
	addr6.address = tuple->src.addr.ipv6;
	addr6.l4_id = tuple->icmp_id;
	*bib = bib_create(&addr4, &addr6, false);
	if (!(*bib)) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a BIB entry.");
		return -ENOMEM;
	}

	/* Add */
	apply_policies();
	error = bib_add(*bib, tuple->l4_proto);
	if (error) {
		bib_dealloc(*bib);
		log_err(ERR_ADD_BIB_FAILED, "Error code %d while adding a BIB entry to the DB.", error);
		return error;
	}

	return 0;
}

static int get_or_create_bib_ipv4(struct tuple *tuple, struct bib_entry **bib)
{
	int error;

	error = bib_get(tuple, bib);
	if (error == -ENOENT) {
		log_warning("There is no BIB entry for the incoming IPv4 ICMP packet.");
		return error;
	} else if (error) {
		log_warning("Error code %d while finding a BIB entry for the incoming packet.", error);
		return error;
	}

	if (address_dependent_filtering() && !session_allow(tuple)) {
		log_info("Packet was blocked by address-dependent filtering.");
		return -EPERM;
	}

	return 0;
}

static int create_session_ipv6(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	struct in_addr ipv4_dst;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	int error;

	/* Translate address from IPv6 to IPv4 */
	if (!extract_ipv4(&tuple->dst.addr.ipv6, &ipv4_dst)) {
		log_err(ERR_EXTRACT_FAILED, "Could not translate the packet's address.");
		return -EINVAL;
	}

	/* Create the session entry */
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

	/* Add the session entry */
	error = session_add(*session);
	if (error) {
		session_dealloc(*session);
		log_err(ERR_ADD_SESSION_FAILED, "Error code %d while adding the session to the DB.", error);
		return error;
	}

	/* Cross-reference them. */
	(*session)->bib = bib;
	list_add(&(*session)->bib_list_hook, &bib->sessions);

	return 0;
}

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

static int create_session_ipv4(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	struct in6_addr ipv6_src;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	int error;

	/* Translate the address */
	if (!append_ipv4(&tuple->src.addr.ipv4, &ipv6_src)) {
		log_err(ERR_APPEND_FAILED, "Could not translate the packet's address.");
		return -EINVAL;
	}

	/* Create the session entry. */
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

	/* Add the session entry */
	error = session_add(*session);
	if (error) {
		session_dealloc(*session);
		log_err(ERR_ADD_SESSION_FAILED, "Error code %d while adding the session to the DB.", error);
		return error;
	}

	/* Cross-reference them. */
	(*session)->bib = bib;
	list_add(&(*session)->bib_list_hook, &bib->sessions);

	return 0;
}

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
 * @param[in] frag first fragment of tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv6_udp(struct fragment *frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;

	spin_lock_bh(&bib_session_lock);

	if (is_error(get_or_create_bib_ipv6(tuple, &bib)))
		goto bib_failure;
	if (is_error(get_or_create_session_ipv6(tuple, bib, &session)))
		goto session_failure;

	set_udp_timer(session);

	spin_unlock_bh(&bib_session_lock);
	return VER_CONTINUE;

session_failure:
	bib_remove(bib, tuple->l4_proto);
	pool4_return(tuple->l4_proto, &bib->ipv4);
	bib_dealloc(bib);
	/* Fall through. */

bib_failure:
	spin_unlock_bh(&bib_session_lock);
	return VER_DROP;
}

/**
 * Assumes that "tuple" represents a IPv4-UDP packet, and filters and updates based on it.
 *
 * This is RFC 6146 section 3.5.1, second half.
 *
 * @param[in] frag first fragment of tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv4_udp(struct fragment* frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;

	spin_lock_bh(&bib_session_lock);

	if (is_error(get_or_create_bib_ipv4(tuple, &bib)))
		goto failure;
	if (is_error(get_or_create_session_ipv4(tuple, bib, &session)))
		goto failure;

	set_udp_timer(session);

	spin_unlock_bh(&bib_session_lock);
	return VER_CONTINUE;

failure:
	spin_unlock_bh(&bib_session_lock);
	return VER_DROP;
}

/**
 * Assumes that "tuple" represents a IPv6-ICMP packet, and filters and updates based on it.
 *
 * This is RFC 6146 section 3.5.3, first half.
 *
 * @param[in] frag first fragment of tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv6_icmp6(struct fragment *frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;

	if (filter_icmpv6_info()) {
		log_info("Packet is ICMPv6 info (ping); dropping due to policy.");
		return VER_DROP;
	}

	spin_lock_bh(&bib_session_lock);

	if (is_error(get_or_create_bib_ipv6(tuple, &bib)))
		goto bib_failure;
	if (is_error(get_or_create_session_ipv6(tuple, bib, &session)))
		goto session_failure;

	set_icmp_timer(session);

	spin_unlock_bh(&bib_session_lock);
	return VER_CONTINUE;

session_failure:
	bib_remove(bib, tuple->l4_proto);
	pool4_return(tuple->l4_proto, &bib->ipv4);
	bib_dealloc(bib);
	/* Fall through. */

bib_failure:
	spin_unlock_bh(&bib_session_lock);
	return VER_DROP;
}

/**
 * Assumes that "tuple" represents a IPv4-ICMP packet, and filters and updates based on it.
 *
 * This is RFC 6146 section 3.5.3, second half.
 *
 * @param[in] frag first fragment of tuple's packet. This is actually only used for error reporting.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict ipv4_icmp4(struct fragment* frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;

	spin_lock_bh(&bib_session_lock);

	if (is_error(get_or_create_bib_ipv4(tuple, &bib)))
		goto failure;
	if (is_error(get_or_create_session_ipv4(tuple, bib, &session)))
		goto failure;

	set_icmp_timer(session);

	spin_unlock_bh(&bib_session_lock);
	return VER_CONTINUE;

failure:
	spin_unlock_bh(&bib_session_lock);
	return VER_DROP;
}

static bool tcp_closed_v6_syn(struct fragment* frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;

	if (is_error(get_or_create_bib_ipv6(tuple, &bib)))
		goto bib_failure;
	if (is_error(create_session_ipv6(tuple, bib, &session)))
		goto session_failure;

	set_tcp_trans_timer(session);
	session->state = V6_INIT;

	return true;

session_failure:
	bib_remove(bib, tuple->l4_proto);
	pool4_return(tuple->l4_proto, &bib->ipv4);
	bib_dealloc(bib);
	/* Fall through. */

bib_failure:
	return false;
}

static inline void store_packet(void)
{
	/* TODO (Issue #58) store the packet. */
	log_warning("Unknown TCP connections started from the IPv4 side are still unsupported."
			"Dropping packet...");
}

static bool tcp_closed_v4_syn(struct fragment* frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	if (drop_external_connections()) {
		log_info("Applying policy: Dropping externally initiated TCP connections.");
		return false;
	}

	error = bib_get(tuple, &bib);
	if (error) {
		if (error == -ENOENT)
			store_packet();
		return false;
	}

	if (is_error(create_session_ipv4(tuple, bib, &session)))
		return false;

	session->state = V4_INIT;
	if (address_dependent_filtering())
		set_syn_timer(session);
	else
		set_tcp_trans_timer(session);

	return true;
}

/**
 * CLOSED state
 *
 * Handle SYN packets.
 *
 * @param[in]   packet  The incoming packet.
 * @param[in]   tuple   Tuple of the incoming packet.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_closed_state_handle(struct fragment* frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	int error = 0;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV6:
		if (frag_get_tcp_hdr(frag)->syn)
			return tcp_closed_v6_syn(frag, tuple);

		/* Look if there is a corresponding entry in the TCP BIB */
		error = bib_get(tuple, &bib);
		if (error)
			log_warning("Error code %d while trying to find a BIB entry for %pI6c#%u.", error,
					&tuple->src.addr.ipv6, tuple->src.l4_id);
		break;

	case L3PROTO_IPV4:
		if (frag_get_tcp_hdr(frag)->syn)
			return tcp_closed_v4_syn(frag, tuple);

		/* Look for the destination transport address (X,x) in the BIB */
		error = bib_get(tuple, &bib);
		if (error)
			log_warning("Error code %d while trying to find a BIB entry for %pI4#%u.", error,
					&tuple->dst.addr.ipv4, tuple->dst.l4_id);
		break;
	}

	return (!error);
}

/**
 * V4 INIT state
 *
 * Handle IPv6 SYN packets.
 *
 * @param[in]   session   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v4_init_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag->l3_hdr.proto == L3PROTO_IPV6 && frag_get_tcp_hdr(frag)->syn) {
		set_tcp_est_timer(session);
		session->state = ESTABLISHED;
	} /* else, the state remains unchanged. */

	return true;
}

/**
 * V6 INIT state.
 *
 * Handle IPv4 & IPv6 SYN packets.
 *
 * @param[in]   session   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v6_init_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag_get_tcp_hdr(frag)->syn) {
		switch (frag->l3_hdr.proto) {
		case L3PROTO_IPV4:
			set_tcp_est_timer(session);
			session->state = ESTABLISHED;
			break;
		case L3PROTO_IPV6:
			set_tcp_trans_timer(session);
			break;
		}
	} /* else, the state remains unchanged */

	return true;
}

/**
 * ESTABLISHED state.
 *
 * Handles V4 FIN, V6 FIN, V4 RST, & V6 RST packets.
 *
 * @param[in]   session   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_established_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag_get_tcp_hdr(frag)->fin) {
		switch (frag->l3_hdr.proto) {
		case L3PROTO_IPV4:
			session->state = V4_FIN_RCV;
			break;
		case L3PROTO_IPV6:
			session->state = V6_FIN_RCV;
			break;
		}

	} else if (frag_get_tcp_hdr(frag)->rst) {
		set_tcp_trans_timer(session);
		session->state = TRANS;
	} else {
		set_tcp_est_timer(session);
	}

	return true;
}

/**
 * V4 FIN RCV state.
 *
 * Handles V6 FIN packets.
 *
 * @param[in]   session   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v4_fin_rcv_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag->l3_hdr.proto == L3PROTO_IPV6 && frag_get_tcp_hdr(frag)->fin) {
		set_tcp_trans_timer(session);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		set_tcp_est_timer(session);
	}
	return true;
}

/**
 * V6 FIN RCV state.
 *
 * Handles V4 FIN packets.
 *
 * @param[in]   session   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v6_fin_rcv_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag->l3_hdr.proto == L3PROTO_IPV4 && frag_get_tcp_hdr(frag)->fin) {
		set_tcp_trans_timer(session);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		set_tcp_est_timer(session);
	}
	return true;
}

/**
 * V6 FIN + V4 FIN RCV state.
 *
 * Handles all packets.
 *
 * @param[in]   session   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_v4_fin_v6_fin_rcv_state_handle(struct fragment *frag,
		struct session_entry *session)
{
	/* Only the timeout can change this state. */
	return true;
}

/**
 * TRANS state.
 *
 * Handles not RST packets.
 *
 * @param[in]   session   Session the packet participates in.
 * @return  true if everything went OK, false otherwise.
 */
static bool tcp_trans_state_handle(struct fragment *frag, struct session_entry *session)
{
	if (!frag_get_tcp_hdr(frag)->rst) {
		set_tcp_est_timer(session);
		session->state = ESTABLISHED;
	}

	return true;
}

/**
 * Assumes that "tuple" represents a TCP packet, and filters and updates based on it.
 * Encapsulates the TCP state machine.
 *
 * This is RFC 6146 section 3.5.2.
 *
 * @param[in] frag first fragment of tuple's packet.
 * @param[in] tuple summary of the packet Jool is currently translating.
 * @return VER_CONTINUE if everything went OK, VER_DROP otherwise.
 */
static verdict tcp(struct fragment* frag, struct tuple *tuple)
{
	struct session_entry *session;
	bool result;
	int error;

	spin_lock_bh(&bib_session_lock);
	error = session_get(tuple, &session);
	if (error != 0 && error != -ENOENT) {
		log_warning("Error code %d while trying to find a TCP session.", error);
		result = false;
		goto end;
	}

	/* If NO session was found: */
	if (error == -ENOENT) {
		result = tcp_closed_state_handle(frag, tuple);
		goto end;
	}

	/* Act according the current state. */
	switch (session->state) {
	case V4_INIT:
		result = tcp_v4_init_state_handle(frag, session);
		break;
	case V6_INIT:
		result = tcp_v6_init_state_handle(frag, session);
		break;
	case ESTABLISHED:
		result = tcp_established_state_handle(frag, session);
		break;
	case V4_FIN_RCV:
		result = tcp_v4_fin_rcv_state_handle(frag, session);
		break;
	case V6_FIN_RCV:
		result = tcp_v6_fin_rcv_state_handle(frag, session);
		break;
	case V4_FIN_V6_FIN_RCV:
		result = tcp_v4_fin_v6_fin_rcv_state_handle(frag, session);
		break;
	case TRANS:
		result = tcp_trans_state_handle(frag, session);
		break;
	default:
		/*
		 * Because closed sessions are not supposed to be stored,
		 * CLOSED is known to fall through here.
		 */
		log_err(ERR_INVALID_STATE, "Invalid state found: %u.", session->state);
		result = false;
	}
	/* Fall through. */

end:
	spin_unlock_bh(&bib_session_lock);
	return result ? VER_CONTINUE : VER_DROP;
}

/**
 * Prepares this module for future use. Avoid calling the rest of the functions unless this has
 * already been executed once.
 *
 * @return zero on success, nonzero on failure.
 */
int filtering_init(void)
{
	config.to.udp = msecs_to_jiffies(1000 * UDP_DEFAULT);
	config.to.icmp = msecs_to_jiffies(1000 * ICMP_DEFAULT);
	config.to.tcp_trans = msecs_to_jiffies(1000 * TCP_TRANS);
	config.to.tcp_est = msecs_to_jiffies(1000 * TCP_EST);
	config.drop_by_addr = FILT_DEF_ADDR_DEPENDENT_FILTERING;
	config.drop_external_tcp = FILT_DEF_DROP_EXTERNAL_CONNECTIONS;
	config.drop_icmp6_info = FILT_DEF_FILTER_ICMPV6_INFO;

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
}

/**
 * Copies this module's current configuration to "clone".
 *
 * @param[out] clone a copy of the current config will be placed here. Must be already allocated.
 * @return zero on success, nonzero on failure.
 */
int clone_filtering_config(struct filtering_config *clone)
{
	spin_lock_bh(&config_lock);
	*clone = config;
	spin_unlock_bh(&config_lock);

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
	int error = 0;
	int udp_min = msecs_to_jiffies(1000 * UDP_MIN);
	int tcp_est = msecs_to_jiffies(1000 * TCP_EST);
	int tcp_trans = msecs_to_jiffies(1000 * TCP_TRANS);

	spin_lock_bh(&config_lock);

	if (operation & DROP_BY_ADDR_MASK)
		config.drop_by_addr = new_config->drop_by_addr;
	if (operation & DROP_ICMP6_INFO_MASK)
		config.drop_icmp6_info = new_config->drop_icmp6_info;
	if (operation & DROP_EXTERNAL_TCP_MASK)
		config.drop_external_tcp = new_config->drop_external_tcp;

	if (operation & UDP_TIMEOUT_MASK) {
		if (new_config->to.udp < udp_min) {
			error = -EINVAL;
			log_err(ERR_UDP_TO_RANGE, "The UDP timeout must be at least %u seconds.", UDP_MIN);
		} else {
			config.to.udp = new_config->to.udp;
		}
	}
	if (operation & ICMP_TIMEOUT_MASK)
		config.to.icmp = new_config->to.icmp;
	if (operation & TCP_EST_TIMEOUT_MASK) {
		if (new_config->to.tcp_est < tcp_est) {
			error = -EINVAL;
			log_err(ERR_TCPEST_TO_RANGE, "The TCP est timeout must be at least %u seconds.",
					TCP_EST);
		} else {
			config.to.tcp_est = new_config->to.tcp_est;
		}
	}
	if (operation & TCP_TRANS_TIMEOUT_MASK) {
		if (new_config->to.tcp_trans < tcp_trans) {
			error = -EINVAL;
			log_err(ERR_TCPTRANS_TO_RANGE, "The TCP trans timeout must be at least %u seconds.",
					TCP_TRANS);
		} else {
			config.to.tcp_trans = new_config->to.tcp_trans;
		}
	}

	spin_unlock_bh(&config_lock);
	return error;
}

/**
 * Main F&U routine. Called during the processing of every packet.
 *
 * Decides if "frag"'s packet must be processed, updating binding and session information.
 *
 * @param[in] frag zero-offset fragment of the packet being translated.
 * @param[in] tuple frag's summary.
 * @return indicator of what should happen to frag.
 */
verdict filtering_and_updating(struct fragment* frag, struct tuple *tuple)
{
	struct in_addr addr4;
	struct ipv6hdr *hdr_ip6;
	struct icmp6hdr *hdr_icmp6;
	struct icmphdr *hdr_icmp4;
	verdict result = VER_CONTINUE;

	log_debug("Step 2: Filtering and Updating");

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV6:
		hdr_icmp6 = frag_get_icmp6_hdr(frag);
		/* ICMP errors should not affect the tables. */
		if (frag->l4_hdr.proto == L4PROTO_ICMP && is_icmp6_error(hdr_icmp6->icmp6_type)) {
			log_debug("Packet is ICMPv6 error; skipping step...");
			return VER_CONTINUE;
		}
		/* Get rid of hairpinning loops and unwanted packets. */
		hdr_ip6 = frag_get_ipv6_hdr(frag);
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
		hdr_icmp4 = frag_get_icmp4_hdr(frag);
		/* ICMP errors should not affect the tables. */
		if (frag->l4_hdr.proto == L4PROTO_ICMP && is_icmp4_error(hdr_icmp4->type)) {
			log_debug("Packet is ICMPv4 error; skipping step...");
			return VER_CONTINUE;
		}
		/* Get rid of unexpected packets */
		addr4.s_addr = frag_get_ipv4_hdr(frag)->daddr;
		if (!pool4_contains(&addr4)) {
			log_info("Packet was rejected by pool4, dropping...");
			return VER_DROP;
		}
		break;
	}

	/* Process packet, according to its protocol. */
	switch (frag->l4_hdr.proto) {
	case L4PROTO_UDP:
		switch (frag->l3_hdr.proto) {
		case L3PROTO_IPV6:
			result = ipv6_udp(frag, tuple);
			break;
		case L3PROTO_IPV4:
			result = ipv4_udp(frag, tuple);
			break;
		}
		break;

	case L4PROTO_TCP:
		result = tcp(frag, tuple);
		break;

	case L4PROTO_ICMP:
		switch (frag->l3_hdr.proto) {
		case L3PROTO_IPV6:
			result = ipv6_icmp6(frag, tuple);
			break;
		case L3PROTO_IPV4:
			result = ipv4_icmp4(frag, tuple);
			break;
		}
		break;

	case L4PROTO_NONE:
		log_err(ERR_ILLEGAL_NONE, "Tuples should not contain the 'NONE' transport protocol.");
		result = VER_DROP;
		break;
	}

	log_debug("Done: Step 2.");
	return result;
}
