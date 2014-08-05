#include "nat64/mod/filtering_and_updating.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/icmp_wrapper.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/pkt_queue.h"
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

static void log_bib(struct bib_entry *bib)
{
	if (bib)
		log_debug("BIB entry: %pI6c#%u - %pI4#%u",
				&bib->ipv6.address, bib->ipv6.l4_id,
				&bib->ipv4.address, bib->ipv4.l4_id);
	else
		log_debug("BIB entry: None");
}

static void log_session(struct session_entry *session)
{
	if (session)
		log_debug("Session entry: %pI6c#%u - %pI6c#%u | %pI4#%u - %pI4#%u",
				&session->ipv6.remote.address, session->ipv6.remote.l4_id,
				&session->ipv6.local.address, session->ipv6.local.l4_id,
				&session->ipv4.local.address, session->ipv4.local.l4_id,
				&session->ipv4.remote.address, session->ipv4.remote.l4_id);
	else
		log_debug("Session entry: None");
}

/**
 * Attempts to find "tuple"'s BIB entry and returns it in "bib".
 * Assumes "tuple" represents a IPv4 packet.
 */
static int get_bib_ipv4(struct sk_buff *skb, struct tuple *tuple, struct bib_entry **bib)
{
	int error;

	error = bibdb_get(tuple, bib);
	if (error == -ENOENT) {
		log_debug("There is no BIB entry for the incoming IPv4 packet.");
		icmp64_send(skb, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	}
	if (error) {
		log_debug("Error code %d while finding a BIB entry for the incoming packet.", error);
		icmp64_send(skb, ICMPERR_ADDR_UNREACHABLE, 0);
		return error;
	}

	if (address_dependent_filtering() && !sessiondb_allow(tuple)) {
		log_debug("Packet was blocked by address-dependent filtering.");
		icmp64_send(skb, ICMPERR_FILTER, 0);
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
		log_debug("Errcode %d while obtaining %pI6c's prefix.", error, &tuple->dst.addr.ipv6);
		return error;
	}

	error = addr_6to4(&tuple->dst.addr.ipv6, &prefix, &ipv4_dst);
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
	pair6.remote.address = tuple->src.addr.ipv6;
	pair6.remote.l4_id = tuple->src.l4_id;
	pair6.local.address = tuple->dst.addr.ipv6;
	pair6.local.l4_id = tuple->dst.l4_id;
	pair4.local = bib->ipv4;
	pair4.remote.address = ipv4_dst;
	pair4.remote.l4_id = (tuple->l4_proto != L4PROTO_ICMP) ? tuple->dst.l4_id : bib->ipv4.l4_id;

	*session = session_create(&pair4, &pair6, tuple->l4_proto, bib);
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		return -ENOMEM;
	}

	apply_policies();

	/* Add it to the table. */
	error = sessiondb_add(*session);
	if (error) {
		session_return(*session);
		log_debug("Error code %d while adding the session to the DB.", error);
		return error;
	}

	return 0;
}

static int create_session_ipv4(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in6_addr ipv6_src;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	int error;

	error = pool6_peek(&prefix);
	if (error)
		return error;

	error = addr_4to6(&tuple->src.addr.ipv4, &prefix, &ipv6_src);
	if (error) {
		log_debug("Error code %d while translating the packet's address.", error);
		return error;
	}

	/*
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	if (bib)
		pair6.remote = bib->ipv6;
	pair6.local.address = ipv6_src;
	pair6.local.l4_id = tuple->src.l4_id;
	pair4.local.address = tuple->dst.addr.ipv4;
	pair4.local.l4_id = tuple->dst.l4_id;
	pair4.remote.address = tuple->src.addr.ipv4;
	pair4.remote.l4_id = tuple->src.l4_id;

	*session = session_create(&pair4, &pair6, tuple->l4_proto, bib);
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		return -ENOMEM;
	}

	apply_policies();

	return 0;
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

	error = bibdb_get_or_create_ipv6(skb, tuple, &bib);
	if (error)
		return VER_DROP;
	log_bib(bib);

	error = sessiondb_get_or_create_ipv6(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}
	log_session(session);

	commit_timer(set_udp_timer(session));

	session_return(session);
	bib_return(bib);

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
	int error;
	struct bib_entry *bib;
	struct session_entry *session;

	error = get_bib_ipv4(skb, tuple, &bib);
	if (error)
		return VER_DROP;
	log_bib(bib);

	error = sessiondb_get_or_create_ipv4(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}
	log_session(session);

	commit_timer(set_udp_timer(session));

	session_return(session);
	bib_return(bib);

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
		log_debug("Packet is ICMPv6 info (ping); dropping due to policy.");
		return VER_DROP;
	}

	error = bibdb_get_or_create_ipv6(skb, tuple, &bib);
	if (error)
		return VER_DROP;
	log_bib(bib);

	error = sessiondb_get_or_create_ipv6(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}
	log_session(session);

	commit_timer(set_icmp_timer(session));

	session_return(session);
	bib_return(bib);

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
	int error;
	struct bib_entry *bib;
	struct session_entry *session;

	error = get_bib_ipv4(skb, tuple, &bib);
	if (error)
		return VER_DROP;
	log_bib(bib);

	error = sessiondb_get_or_create_ipv4(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return VER_DROP;
	}
	log_session(session);

	commit_timer(set_icmp_timer(session));

	session_return(session);
	bib_return(bib);

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

	error = bibdb_get_or_create_ipv6(skb, tuple, &bib);
	if (error)
		return error;
	log_bib(bib);

	error = create_session_ipv6(tuple, bib, &session);
	if (error) {
		bib_return(bib);
		return error;
	}
	log_session(session);

	commit_timer(set_tcp_trans_timer(session));
	session->state = V6_INIT;

	session_return(session);
	bib_return(bib);

	return 0;
}

/**
 * Second half of the filtering and updating done during the CLOSED state of the TCP state machine.
 * Processes IPv4 SYN packets when there's no state.
 * Part of RFC 6146 section 3.5.2.2.
 */
static verdict tcp_closed_v4_syn(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	struct session_entry *session;
	int error;
	verdict result = VER_DROP;

	if (drop_external_connections()) {
		log_debug("Applying policy: Dropping externally initiated TCP connections.");
		return VER_DROP;
	}

	error = bibdb_get(tuple, &bib);
	if (error) {
		if (error != -ENOENT)
			return VER_DROP;
		bib = NULL;
	}
	log_bib(bib);

	error = create_session_ipv4(tuple, bib, &session);
	if (error)
		goto end_bib;
	log_session(session);

	session->state = V4_INIT;

	if (!bib || address_dependent_filtering()) {
		error = pktqueue_add(session, skb);
		if (error)
			goto end_session;

		commit_timer(set_syn_timer(session));
		result = VER_STOLEN;

	} else {
		error = sessiondb_add(session);
		if (error) {
			log_debug("Error code %d while adding the session to the DB.", error);
			goto end_session;
		}

		commit_timer(set_tcp_trans_timer(session));
		result = VER_CONTINUE;
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
static verdict tcp_closed_state_handle(struct sk_buff *skb, struct tuple *tuple)
{
	struct bib_entry *bib;
	int error;

	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV6:
		if (tcp_hdr(skb)->syn)
			return is_error(tcp_closed_v6_syn(skb, tuple)) ? VER_DROP : VER_CONTINUE;
		break;

	case L3PROTO_IPV4:
		if (tcp_hdr(skb)->syn)
			return tcp_closed_v4_syn(skb, tuple);
		break;
	}

	error = bibdb_get(tuple, &bib);
	if (error) {
		log_debug("Closed state: Packet is not SYN and there is no BIB entry, so discarding. "
				"ERRcode %d", error);
		return VER_DROP;
	}

	bib_return(bib);
	return VER_CONTINUE;
}

/**
 * Filtering and updating done during the V4 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_init_state_handle(struct sk_buff *skb, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (skb_l3_proto(skb) == L3PROTO_IPV6 && tcp_hdr(skb)->syn) {
		pktqueue_remove(session); /* The packet might have not been stored, so ignore errors. */

		*expirer = set_tcp_est_timer(session);
		session->state = ESTABLISHED;
	} /* else, the state remains unchanged. */

	return 0;
}

/**
 * Filtering and updating done during the V6 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_init_state_handle(struct sk_buff *skb, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (tcp_hdr(skb)->syn) {
		switch (skb_l3_proto(skb)) {
		case L3PROTO_IPV4:
			*expirer = set_tcp_est_timer(session);
			session->state = ESTABLISHED;
			break;
		case L3PROTO_IPV6:
			*expirer = set_tcp_trans_timer(session);
			break;
		}
	} /* else, the state remains unchanged */

	return 0;
}

/**
 * Filtering and updating done during the ESTABLISHED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_established_state_handle(struct sk_buff *skb, struct session_entry *session,
		struct expire_timer **expirer)
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
		*expirer = set_tcp_trans_timer(session);
		session->state = TRANS;
	} else {
		*expirer = set_tcp_est_timer(session);
	}

	return 0;
}

/**
 * Filtering and updating done during the V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_rcv_state_handle(struct sk_buff *skb, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (skb_l3_proto(skb) == L3PROTO_IPV6 && tcp_hdr(skb)->fin) {
		*expirer = set_tcp_trans_timer(session);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		*expirer = set_tcp_est_timer(session);
	}
	return 0;
}

/**
 * Filtering and updating done during the V6 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_fin_rcv_state_handle(struct sk_buff *skb, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (skb_l3_proto(skb) == L3PROTO_IPV4 && tcp_hdr(skb)->fin) {
		*expirer = set_tcp_trans_timer(session);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		*expirer = set_tcp_est_timer(session);
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
static int tcp_trans_state_handle(struct sk_buff *skb, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (!tcp_hdr(skb)->rst) {
		*expirer = set_tcp_est_timer(session);
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
	struct expire_timer *expirer = NULL;
	int error;

	error = sessiondb_get(tuple, &session);
	if (error != 0 && error != -ENOENT) {
		log_debug("Error code %d while trying to find a TCP session.", error);
		goto end;
	}

	/* If NO session was found: */
	if (error == -ENOENT)
		return tcp_closed_state_handle(skb, tuple);

	log_session(session);

	spin_lock_bh(&session->lock);
	/* Act according the current state. */
	switch (session->state) {
	case V4_INIT:
		error = tcp_v4_init_state_handle(skb, session, &expirer);
		break;
	case V6_INIT:
		error = tcp_v6_init_state_handle(skb, session, &expirer);
		break;
	case ESTABLISHED:
		error = tcp_established_state_handle(skb, session, &expirer);
		break;
	case V4_FIN_RCV:
		error = tcp_v4_fin_rcv_state_handle(skb, session, &expirer);
		break;
	case V6_FIN_RCV:
		error = tcp_v6_fin_rcv_state_handle(skb, session, &expirer);
		break;
	case V4_FIN_V6_FIN_RCV:
		error = tcp_v4_fin_v6_fin_rcv_state_handle(skb, session);
		break;
	case TRANS:
		error = tcp_trans_state_handle(skb, session, &expirer);
		break;
	default:
		/*
		 * Because closed sessions are not supposed to be stored,
		 * CLOSED is known to fall through here.
		 */
		WARN(true, "Invalid state found: %u.", session->state);
		error = -EINVAL;
	}

	spin_unlock_bh(&session->lock);

	commit_timer(expirer);
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
		log_debug("Could not allocate memory to store the filtering config.");
		return -ENOMEM;
	}

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
int filtering_clone_config(struct filtering_config *clone)
{
	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	rcu_read_unlock_bh();
	return 0;
}

/**
 * Updates the configuration value of this module whose identifier is "type".
 *
 * @param type ID of the configuration value you want to edit.
 * @size length of "value" in bytes.
 * @value the new value you want the field to have.
 */
int filtering_set_config(enum filtering_type type, size_t size, void *value)
{
	struct filtering_config *tmp_config;
	struct filtering_config *old_config;
	__u8 value8;

	if (size != sizeof(__u8)) {
		log_debug("Expected a boolean, got %zu bytes.", size);
		return -EINVAL;
	}
	value8 = *((__u8 *) value);

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	switch (type) {
	case DROP_BY_ADDR:
		tmp_config->drop_by_addr = value8;
		break;
	case DROP_ICMP6_INFO:
		tmp_config->drop_icmp6_info = value8;
		break;
	case DROP_EXTERNAL_TCP:
		tmp_config->drop_external_tcp = value8;
		break;
	default:
		log_err("Unknown config type for the 'filtering and updating' module: %u", type);
		kfree(tmp_config);
		return -EINVAL;
	}

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();
	kfree(old_config);

	return 0;
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
			log_debug("Hairpinning loop. Dropping...");
			return VER_DROP;
		}
		if (!pool6_contains(&hdr_ip6->daddr)) {
			log_debug("Packet was rejected by pool6, dropping...");
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
			log_debug("Packet was rejected by pool4, dropping...");
			return VER_DROP;
		}
		break;
	}

	/* Process packet, according to its protocol. */

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
	}

	log_debug("Done: Step 2.");
	return result;
}
