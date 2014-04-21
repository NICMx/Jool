#include "nat64/mod/filtering_and_updating.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/icmp_wrapper.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/pool4.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/session_db.h"
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

/**
 * Marks "session" to be destroyed after the UDP session lifetime has lapsed.
 */
static void set_udp_timer(struct session_entry *session)
{
	__u64 ttl;

	rcu_read_lock_bh();
	ttl = rcu_dereference_bh(config)->to.udp;
	rcu_read_unlock_bh();

	sessiondb_update_timer(session, TIMERTYPE_UDP, ttl);
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

	sessiondb_update_timer(session, TIMERTYPE_TCP_EST, ttl);
}

/**
 * Marks "session" to be destroyed after the transitory TCP session lifetime has lapsed.
 */
void set_tcp_trans_timer(struct session_entry *session)
{
	__u64 ttl;

	rcu_read_lock_bh();
	ttl = rcu_dereference_bh(config)->to.tcp_trans;
	rcu_read_unlock_bh();

	sessiondb_update_timer(session, TIMERTYPE_TCP_TRANS, ttl);
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

	sessiondb_update_timer(session, TIMERTYPE_ICMP, ttl);
}

/**
 * Marks "session" to be destroyed after TCP_INCOMING_SYN seconds have lapsed.
 */
/*
static void set_syn_timer(struct session_entry *session)
{
	__u64 ttl = msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
	sessiondb_update_timer(session, TIMERTYPE_TCP_SYN, ttl);
}
*/


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

/**
 * Decides whether the packet should be filtered or not. Not yet implemented.
 */
static inline void apply_policies(void)
{
	/* TODO (Issue #41) decide whether resources and policy allow filtering to continue. */
}

/**
 * Assumes that "tuple" represents a IPv4 packet, and attempts to find its BIB entry, returning it
 * in "bib". If the entry doesn't exist, it is created.
 */
static int get_bib_ipv4(struct fragment *frag, struct tuple *tuple,
		struct bib_entry **bib)
{
	int error;

	error = bibdb_get(tuple, bib);
	if (error == -ENOENT) {
		log_info("There is no BIB entry for the incoming IPv4 packet.");
		icmp64_send(frag, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	}
	if (error) {
		log_warning("Error code %d while finding a BIB entry for the incoming packet.", error);
		icmp64_send(frag, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	}

	if (address_dependent_filtering() && !sessiondb_allow(tuple)) {
		log_info("Packet was blocked by address-dependent filtering.");
		icmp64_send(frag, ICMPERR_FILTER, 0);
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
	error = sessiondb_add(*session);
	if (error) {
		log_err(ERR_ADD_SESSION_FAILED, "Error code %d while adding the session to the DB.", error);
		session_kfree(*session);
		return error;
	}

	bib_get(bib);/* increment the refcounter +1, related to this session*/
	(*session)->bib = bib;

	return 0;
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
	error = sessiondb_add(*session);
	if (error) {
		log_err(ERR_ADD_SESSION_FAILED, "Error code %d while adding the session to the DB.", error);
		session_kfree(*session);
		return error;
	}

	bib_get(bib);/* increment the refcounter +1, related to this session*/
	(*session)->bib = bib;

	return 0;
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
	int error;

	error = bibdb_get_or_create_ipv6(frag, tuple, &bib);
	if (error)
		return VER_DROP;


	error = sessiondb_get_or_create_ipv6(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}

	set_udp_timer(session);

	session_return(session);
	bib_return(bib);

	return VER_CONTINUE;
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
	int error;
	struct bib_entry *bib;
	struct session_entry *session;

	error = get_bib_ipv4(frag, tuple, &bib);
	if (error)
		return VER_DROP;

	error = sessiondb_get_or_create_ipv4(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}

	set_udp_timer(session);

	session_return(session);
	bib_return(bib);

	return VER_CONTINUE;
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
	int error;

	if (filter_icmpv6_info()) {
		log_info("Packet is ICMPv6 info (ping); dropping due to policy.");
		return VER_DROP;
	}

	error = bibdb_get_or_create_ipv6(frag, tuple, &bib);
	if (error)
		return VER_DROP;


	error = sessiondb_get_or_create_ipv6(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}

	set_icmp_timer(session);

	session_return(session);
	bib_return(bib);

	return VER_CONTINUE;
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
	int error;
	struct bib_entry *bib;
	struct session_entry *session;

	error = get_bib_ipv4(frag, tuple, &bib);
	if (error)
		return VER_DROP;

	error = sessiondb_get_or_create_ipv4(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}

	set_icmp_timer(session);

	session_return(session);
	bib_return(bib);

	return VER_CONTINUE;
}

/**
 * First half of the filtering and updating done during the CLOSED state of the TCP state machine.
 * Processes IPv6 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_closed_v6_syn(struct fragment* frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;

	error = bibdb_get_or_create_ipv6(frag, tuple, &bib);
	if (error)
		return error;

	error = create_session_ipv6(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return error;
	}

	set_tcp_trans_timer(session);
	session->state = V6_INIT;

	session_return(session);
	bib_return(bib);

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
static int tcp_closed_v4_syn(struct fragment* frag, struct tuple *tuple)
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

	error = bibdb_get(tuple, &bib);
	if (error) {
		if (error == -ENOENT)
			store_packet();
		return error;
	}

	error = create_session_ipv4(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return error;
	}

	session->state = V4_INIT;
	set_tcp_trans_timer(session);
	session_return(session);
	bib_return(bib);

	return 0;
}

/**
 * Filtering and updating done during the CLOSED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_closed_state_handle(struct fragment* frag, struct tuple *tuple)
{
	struct bib_entry *bib;
	int error;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV6:
		if (frag_get_tcp_hdr(frag)->syn)
			return tcp_closed_v6_syn(frag, tuple);
		break;

	case L3PROTO_IPV4:
		if (frag_get_tcp_hdr(frag)->syn)
			return tcp_closed_v4_syn(frag, tuple);
		break;
	}

	error = bibdb_get(tuple, &bib);
	if (bib)
		bib_return(bib);

	return error;
}

/**
 * Filtering and updating done during the V4 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_init_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag->l3_hdr.proto == L3PROTO_IPV6 && frag_get_tcp_hdr(frag)->syn) {
		set_tcp_est_timer(session);
		session->state = ESTABLISHED;
	} /* else, the state remains unchanged. */

	return 0;
}

/**
 * Filtering and updating done during the V6 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_init_state_handle(struct fragment* frag, struct session_entry *session)
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

	return 0;
}

/**
 * Filtering and updating done during the ESTABLISHED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_established_state_handle(struct fragment* frag, struct session_entry *session)
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

	return 0;
}

/**
 * Filtering and updating done during the V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_rcv_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag->l3_hdr.proto == L3PROTO_IPV6 && frag_get_tcp_hdr(frag)->fin) {
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
static int tcp_v6_fin_rcv_state_handle(struct fragment* frag, struct session_entry *session)
{
	if (frag->l3_hdr.proto == L3PROTO_IPV4 && frag_get_tcp_hdr(frag)->fin) {
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
static int tcp_v4_fin_v6_fin_rcv_state_handle(struct fragment *frag,
		struct session_entry *session)
{
	return 0; /* Only the timeout can change this state. */
}

/**
 * Filtering and updating done during the TRANS state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_trans_state_handle(struct fragment *frag, struct session_entry *session)
{
	if (!frag_get_tcp_hdr(frag)->rst) {
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
static verdict tcp(struct fragment* frag, struct tuple *tuple)
{
	struct session_entry *session;
	int error;

	error = sessiondb_get(tuple, &session);
	if (error != 0 && error != -ENOENT) {
		log_warning("Error code %d while trying to find a TCP session.", error);
		goto end;
	}

	/* If NO session was found: */
	if (error == -ENOENT) {
		error = tcp_closed_state_handle(frag, tuple);
		goto end;
	}

	/* Act according the current state. */
	switch (session->state) {
	case V4_INIT:
		error = tcp_v4_init_state_handle(frag, session);
		break;
	case V6_INIT:
		error = tcp_v6_init_state_handle(frag, session);
		break;
	case ESTABLISHED:
		error = tcp_established_state_handle(frag, session);
		break;
	case V4_FIN_RCV:
		error = tcp_v4_fin_rcv_state_handle(frag, session);
		break;
	case V6_FIN_RCV:
		error = tcp_v6_fin_rcv_state_handle(frag, session);
		break;
	case V4_FIN_V6_FIN_RCV:
		error = tcp_v4_fin_v6_fin_rcv_state_handle(frag, session);
		break;
	case TRANS:
		error = tcp_trans_state_handle(frag, session);
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
	session_return(session);

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

	return 0;
}

/**
 * Frees any memory allocated by this module.
 */
void filtering_destroy(void)
{
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
