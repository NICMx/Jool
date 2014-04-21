#include "nat64/mod/session_db.h"

#include <net/ipv6.h>
#include "nat64/mod/rbtree.h"
#include "nat64/mod/session.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/send_packet.h"
#include "nat64/mod/filtering_and_updating.h"


/********************************************
 * Structures and private variables.
 ********************************************/


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


/**
 * Session table definition.
 * Holds two hash tables, one for each indexing need (IPv4 and IPv6).
 */
struct session_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;
	/* spinlock for the table */
	spinlock_t session_table_lock;

	u64 count;
};

/** The session table for UDP connections. */
static struct session_table session_table_udp;
/** The session table for TCP connections. */
static struct session_table session_table_tcp;
/** The session table for ICMP connections. */
static struct session_table session_table_icmp;

/********************************************
 * Private (helper) functions.
 ********************************************/

static int get_session_table(l4_protocol l4_proto, struct session_table **result)
{
	switch (l4_proto) {
	case L4PROTO_UDP:
		*result = &session_table_udp;
		return 0;
	case L4PROTO_TCP:
		*result = &session_table_tcp;
		return 0;
	case L4PROTO_ICMP:
		*result = &session_table_icmp;
		return 0;
	case L4PROTO_NONE:
		log_crit(ERR_L4PROTO, "There is no session table for the 'NONE' protocol.");
		return -EINVAL;
	}

	log_crit(ERR_L4PROTO, "Unsupported transport protocol: %u.", l4_proto);
	return -EINVAL;
}

static void tuple_to_ipv6_pair(struct tuple *tuple, struct ipv6_pair *pair)
{
	pair->remote.address = tuple->src.addr.ipv6;
	pair->remote.l4_id = tuple->src.l4_id;
	pair->local.address = tuple->dst.addr.ipv6;
	pair->local.l4_id = tuple->dst.l4_id;
}

static void tuple_to_ipv4_pair(struct tuple *tuple, struct ipv4_pair *pair)
{
	pair->remote.address = tuple->src.addr.ipv4;
	pair->remote.l4_id = tuple->src.l4_id;
	pair->local.address = tuple->dst.addr.ipv4;
	pair->local.l4_id = tuple->dst.l4_id;
}

static int compare_full6(struct session_entry *session, struct ipv6_pair *pair)
{
	int gap;

	gap = ipv6_addr_cmp(&session->ipv6.local.address, &pair->local.address);
	if (gap != 0)
		return gap;

	gap = ipv6_addr_cmp(&session->ipv6.remote.address, &pair->remote.address);
	if (gap != 0)
		return gap;

	gap = session->ipv6.local.l4_id - pair->local.l4_id;
	if (gap != 0)
		return gap;

	gap = session->ipv6.remote.l4_id - pair->remote.l4_id;
	return gap;
}

static int compare_addrs4(struct session_entry *session, struct ipv4_pair *pair)
{
	int gap;

	gap = ipv4_addr_cmp(&session->ipv4.local.address, &pair->local.address);
	if (gap != 0)
		return gap;

	gap = session->ipv4.local.l4_id - pair->local.l4_id;
	if (gap != 0)
		return gap;

	gap = ipv4_addr_cmp(&session->ipv4.remote.address, &pair->remote.address);
	return gap;
}

static int compare_full4(struct session_entry *session, struct ipv4_pair *pair)
{
	int gap;

	gap = compare_addrs4(session, pair);
	if (gap != 0)
		return gap;

	gap = session->ipv4.remote.l4_id - pair->remote.l4_id;
	return gap;
}

static int compare_local4(struct session_entry *session, struct ipv4_tuple_address *addr)
{
	int gap;

	gap = ipv4_addr_cmp(&session->ipv4.local.address, &addr->address);
	if (gap != 0)
		return gap;

	gap = session->ipv4.local.l4_id - addr->l4_id;
	return gap;
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
	struct dst_entry *dst;
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

	dst = route_ipv6(iph, th, L4PROTO_TCP, 0);
	if (!dst) {
		log_warning("Could now route the probe packet.");
		goto fail;
	}
	skb->dev = dst->dev;
	skb_dst_set(skb, dst);

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
	unsigned int s = 0;

	list_for_each_safe(current_hook, next_hook, list) {
		session = list_entry(current_hook, struct session_entry, expire_list_hook);
		session_get(session);

		if (time_before(jiffies, session->dying_time)) {
			log_debug("Deleted %u sessions", s);
			session_return(session); /* we need to decrement by one the reference of session */
			return false;
		}
		if (!session_expire(session)) {
			session_return(session); /* we need to decrement by one the reference of session */
			continue; /* The entry's TTL changed, which doesn't mean the next one isn't expired. */
		}

		if (is_error(sessiondb_remove(session))) {
			session_return(session); /* we need to decrement by one the reference of session */
			continue; /* Error msg already printed. */
		}

//		bib = session->bib;
//		l4_proto = session->l4_proto;

		list_del(&session->expire_list_hook);

		if (session_return(session)) {
			s++;
		}
//		s++;

//		if (!bib) {
//			log_crit(ERR_NULL, "The session entry I just removed had no BIB entry."); /* ?? */
//			continue;
//		}
//		if (atomic_read(&bib->sessions_counter) || bib->is_static) {
//			continue; /* The BIB entry needn't die; no error to report. */
//		}
//		if (bib->is_static) {
//			continue; /* The BIB entry needn't die; no error to report. */
//		}
//		if (is_error(bibdb_remove(bib, l4_proto))) {
//			continue; /* Error msg already printed. */
//		}
//		if (!bib_return(bib)) {
//			continue; /* The BIB entry was not removed from the DB. */
//		}
//		b++;
	}

	log_debug("Deleted %u sessions", s);

	return true;
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
 * Called once in a while to kick off the scheduled expired sessions massacre.
 */
static void cleaner_timer(unsigned long param)
{
	bool clean = true;

	log_debug("===============================================");
	log_debug("Deleting expired sessions...");

	spin_lock_bh(&session_table_udp.session_table_lock);
	clean &= clean_expired_sessions(&sessions_udp);
	spin_unlock_bh(&session_table_udp.session_table_lock);

	spin_lock_bh(&session_table_tcp.session_table_lock);
	clean &= clean_expired_sessions(&sessions_tcp_est);
	clean &= clean_expired_sessions(&sessions_tcp_trans);
	clean &= clean_expired_sessions(&sessions_syn);
	spin_unlock_bh(&session_table_tcp.session_table_lock);

	spin_lock_bh(&session_table_icmp.session_table_lock);
	clean &= clean_expired_sessions(&sessions_icmp);
	spin_unlock_bh(&session_table_icmp.session_table_lock);

	log_debug("Session database cleaned successfully.");

	if (!clean) {
		mod_timer(&expire_timer, get_next_dying_time());
		log_debug("The timer will awake again in %u msecs.",
				jiffies_to_msecs(expire_timer.expires - jiffies));
	}
}

/*******************************
 * Public functions.
 *******************************/

int sessiondb_init(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;
	int error;

	error = session_init();
	if (error)
		return error;

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		tables[i]->tree6 = RB_ROOT;
		tables[i]->tree4 = RB_ROOT;
		tables[i]->count = 0;
		spin_lock_init(&tables[i]->session_table_lock);
	}

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

static void session_destroy_aux(struct rb_node *node)
{
	session_kfree(rb_entry(node, struct session_entry, tree6_hook));
//	session_return(rb_entry(node, struct session_entry, tree6_hook));
//	session_return(rb_entry(node, struct session_entry, tree6_hook));
}

void sessiondb_destroy(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;

	del_timer_sync(&expire_timer);

	log_debug("Emptying the session tables...");
	/*
	 * The values need to be released only in one of the trees
	 * because both trees point to the same values.
	 */
	for (i = 0; i < ARRAY_SIZE(tables); i++)
		rbtree_clear(&tables[i]->tree6, session_destroy_aux);

	session_destroy();
}

int sessiondb_get_by_ipv4(struct ipv4_pair *pair, l4_protocol l4_proto,
		struct session_entry **result)
{
	struct session_table *table;
	int error;

	if (!pair) {
		log_warning("The session tables cannot contain NULL.");
		return -EINVAL;
	}
	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->session_table_lock);
	*result = rbtree_find(pair, &table->tree4, compare_full4, struct session_entry, tree4_hook);
	if (*result)
		session_get(*result);
	spin_unlock_bh(&table->session_table_lock);

	return (*result) ? 0 : -ENOENT;
}

int sessiondb_get_by_ipv6(struct ipv6_pair *pair, l4_protocol l4_proto,
		struct session_entry **result)
{
	struct session_table *table;
	int error;

	if (!pair) {
		log_warning("The session tables cannot contain NULL.");
		return -EINVAL;
	}
	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->session_table_lock);
	*result = rbtree_find(pair, &table->tree6, compare_full6, struct session_entry, tree6_hook);
	if (*result)
		session_get(*result);
	spin_unlock_bh(&table->session_table_lock);

	return (*result) ? 0 : -ENOENT;
}

int sessiondb_get(struct tuple *tuple, struct session_entry **result)
{
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;

	if (!tuple) {
		log_err(ERR_NULL, "There's no session entry mapped to NULL.");
		return -EINVAL;
	}

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		tuple_to_ipv6_pair(tuple, &pair6);
		return sessiondb_get_by_ipv6(&pair6, tuple->l4_proto, result);
	case L3PROTO_IPV4:
		tuple_to_ipv4_pair(tuple, &pair4);
		return sessiondb_get_by_ipv4(&pair4, tuple->l4_proto, result);
	}

	log_crit(ERR_L3PROTO, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

bool sessiondb_allow(struct tuple *tuple)
{
	struct session_table *table;
	struct session_entry *session;
	struct ipv4_pair tuple_pair;
	int error;

	/* Sanity */
	if (!tuple) {
		log_err(ERR_NULL, "Cannot extract addresses from NULL.");
		return false;
	}
	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	spin_lock_bh(&table->session_table_lock);
	tuple_to_ipv4_pair(tuple, &tuple_pair);
	session = rbtree_find(&tuple_pair, &table->tree4, compare_addrs4, struct session_entry,
			tree4_hook);
	spin_unlock_bh(&table->session_table_lock);

	return (session) ? true : false;
}

int sessiondb_add(struct session_entry *session)
{
	struct session_table *table;
	int error;

	/* Sanity */
	if (!session) {
		log_err(ERR_NULL, "Cannot insert NULL as a session session.");
		return -EINVAL;
	}
	error = get_session_table(session->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	spin_lock_bh(&table->session_table_lock);

	error = rbtree_add(session, ipv6, &table->tree6, compare_full6, struct session_entry, tree6_hook);
	if (error) {
		spin_unlock_bh(&table->session_table_lock);
		return -EEXIST;
	}
	session_get(session); /* increment the refcounter +1, related to the tree6_hook reference */

	error = rbtree_add(session, ipv4, &table->tree4, compare_full4, struct session_entry, tree4_hook);
	if (error) { /*this is not supposed to happen in a perfect world*/
		log_crit(ERR_ADD_BIB_FAILED, "The session was inserted in Session_table_tree6 but exist in Session_table_tree4");
		rb_erase(&session->tree6_hook, &table->tree6);
		spin_unlock_bh(&table->session_table_lock);
		return -EEXIST;
	}
	session_get(session); /* increment the refcounter +1, related to the tree4_hook reference*/

	table->count++;
	spin_unlock_bh(&table->session_table_lock);
	return 0;
}

int sessiondb_remove(struct session_entry *entry)
{
	struct session_table *table;
	int error;

	/* Sanity */
	if (!entry) {
		log_err(ERR_NULL, "The Session tables do not contain NULL entries.");
		return -EINVAL;
	}
	error = get_session_table(entry->l4_proto, &table);
	if (error)
		return error;

	/* Action */
//	spin_lock_bh(&table->session_table_lock);

	rb_erase(&entry->tree6_hook, &table->tree6);
	session_return(entry);
	rb_erase(&entry->tree4_hook, &table->tree4);
	session_return(entry);

	table->count--;
//	spin_unlock_bh(&table->session_table_lock);
	return 0;
}

int sessiondb_for_each(l4_protocol l4_proto, int (*func)(struct session_entry *, void *), void *arg)
{
	struct session_table *table;
	struct rb_node *node;
	int error;

	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->session_table_lock);
	for (node = rb_first(&table->tree4); node; node = rb_next(node)) {
		error = func(rb_entry(node, struct session_entry, tree4_hook), arg);
		if (error) {
			spin_unlock_bh(&table->session_table_lock);
			return error;
		}
	}

	spin_unlock_bh(&table->session_table_lock);
	return 0;
}

int sessiondb_count(l4_protocol proto, __u64 *result)
{
	struct session_table *table;
	int error;

	error = get_session_table(proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->session_table_lock);
	*result = table->count;
	spin_unlock_bh(&table->session_table_lock);
	return 0;
}

int sessiondb_get_or_create_ipv6(struct tuple *tuple, struct bib_entry *bib, struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in_addr ipv4_dst;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	struct rb_node **node, *parent;
	struct session_table *table;
	int error;

	if (!tuple) {
		log_err(ERR_NULL, "There's no session entry mapped to NULL.");
		return -EINVAL;
	}

	tuple_to_ipv6_pair(tuple, &pair6);

	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->session_table_lock);
	error = rbtree_find_node(&pair6, &table->tree6, compare_full6, struct session_entry, tree6_hook, parent, node);
	if (*node) {
		*session = rb_entry(*node, struct session_entry, tree6_hook);
		session_get(*session);
		spin_unlock_bh(&table->session_table_lock);
		return 0;
	}
	/*doesn't found a session, so we will create one session*/

	/* Translate address from IPv6 to IPv4 */
	error = pool6_get(&tuple->dst.addr.ipv6, &prefix);
	if (error) {
		log_warning("Errcode %d while obtaining %pI6c's prefix.", error, &tuple->dst.addr.ipv6);
		spin_unlock_bh(&table->session_table_lock);
		return error;
	}

	error = addr_6to4(&tuple->dst.addr.ipv6, &prefix, &ipv4_dst);
	if (error) {
		log_err(ERR_EXTRACT_FAILED, "Error code %d while translating the packet's address.", error);
		spin_unlock_bh(&table->session_table_lock);
		return error;
	}

	/*
	 * Create the session entry.
	 *
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	pair4.local = bib->ipv4;
	pair4.remote.address = ipv4_dst;
	pair4.remote.l4_id = (tuple->l4_proto != L4PROTO_ICMP) ? tuple->dst.l4_id : bib->ipv4.l4_id;
	*session = session_create(&pair4, &pair6, tuple->l4_proto); /*refcounter is set to 1 when its created*/
	if (!(*session)) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
		spin_unlock_bh(&table->session_table_lock);
		return -ENOMEM;
	}

	/* add a new node and rebalance the tree */
	rb_link_node(&(*session)->tree6_hook, parent, node);
	rb_insert_color(&(*session)->tree6_hook, &table->tree6);
	session_get(*session); /*tree6 reference +2*/

	error = rbtree_add(*session, ipv4, &table->tree4, compare_full4, struct session_entry, tree4_hook);
	session_get(*session); /*tree4 reference +3*/
	if (error) {
		log_crit(ERR_ADD_SESSION_FAILED, "The entry session was inserted in session_table_tree6 but exist in session_table_tree4");
		rb_erase(&(*session)->tree6_hook, &table->tree6);
		session_kfree(*session);
		spin_unlock_bh(&table->session_table_lock);
		return error;
	}

	bib_get(bib);
	(*session)->bib = bib;
	spin_unlock_bh(&table->session_table_lock);
	return 0;
}


int sessiondb_get_or_create_ipv4(struct tuple *tuple, struct bib_entry *bib, struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in6_addr ipv6_src;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	struct rb_node **node, *parent;
	struct session_table *table;
	int error;

	if (!tuple) {
		log_err(ERR_NULL, "There's no session entry mapped to NULL.");
		return -EINVAL;
	}

	tuple_to_ipv4_pair(tuple, &pair4);

	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->session_table_lock);
	error = rbtree_find_node(&pair4, &table->tree4, compare_full4, struct session_entry, tree4_hook, parent, node);
	if (*node) {
		*session = rb_entry(*node, struct session_entry, tree4_hook);
		session_get(*session);
		spin_unlock_bh(&table->session_table_lock);
		return 0;
	}
	/*doesn't found a session, so we will create one session*/

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
	*session = session_create(&pair4, &pair6, tuple->l4_proto); /*refcounter is set to 1 when its created*/
	if (!(*session)) {
		log_err(ERR_ALLOC_FAILED, "Failed to allocate a session entry.");
		spin_unlock_bh(&table->session_table_lock);
		return -ENOMEM;
	}

	/* add a new node and rebalance the tree */
	rb_link_node(&(*session)->tree4_hook, parent, node);
	rb_insert_color(&(*session)->tree4_hook, &table->tree4);
	session_get(*session); /*tree6 reference +2*/

	error = rbtree_add(*session, ipv6, &table->tree6, compare_full6, struct session_entry, tree6_hook);
	session_get(*session); /*tree4 reference +3*/
	if (error) {
		log_crit(ERR_ADD_SESSION_FAILED, "The entry session was inserted in session_table_tree6 but exist in session_table_tree4");
		rb_erase(&(*session)->tree4_hook, &table->tree4);
		session_kfree(*session);
		spin_unlock_bh(&table->session_table_lock);
		return error;
	}

	bib_get(bib);
	(*session)->bib = bib;
	spin_unlock_bh(&table->session_table_lock);
	return 0;
}

/*******************************************
 * Helper function for static_routes.c delete
 *******************************************/

int sessiondb_delete_by_bib(struct bib_entry *bib)
{
	struct session_table *table;
	struct session_entry *session;
	struct ipv4_tuple_address *addr;
	struct rb_node *node;
	int error;
	int s = 0;
	bool found;

	addr = &bib->ipv4;

	/* Sanitize */
	if (!addr)
		return -EINVAL;
	error = get_session_table(bib->l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->session_table_lock);
	/* Find the top-most node in the tree whose IPv4 address is addr. */
	session = rbtree_find(addr, &table->tree4, compare_local4, struct session_entry, tree4_hook);
	if (!session) {
		spin_unlock_bh(&table->session_table_lock);
		return 0; /* _Successfully_ iterated through no entries. */
	}

	/* Keep moving left until we find the first node whose IPv4 address is addr. */
	found = false;
	do {
		node = rb_prev(&session->tree4_hook);

		if (node) {
			struct session_entry *tmp = rb_entry(node, struct session_entry, tree4_hook);
			if (compare_local4(tmp, addr))
				found = true;
			else
				session = tmp;
		} else {
			found = true;
		}
	} while (!found);

	/*
	 * Keep moving right until the address changes.
	 * (The nodes are sorted by address first.)
	 */
	do {
		/***
		 * primero nos aseguramos de referenciar al nodo siguiente antes de eliminar la session a la que
		 * apuntamos actualmente
		 */
		node = rb_next(&session->tree4_hook);

		list_del(&session->expire_list_hook); /* we should delete the expire_list_hook of the session. */
		/**
		 * eliminamos la session de la BD
		 */
		rb_erase(&session->tree6_hook, &table->tree6);
		session_return(session);
		rb_erase(&session->tree4_hook, &table->tree4);

		if (session_return(session))
			s++;
		table->count--;

		if (!node)
			break;
		session = rb_entry(node, struct session_entry, tree4_hook);
	} while (ipv4_addr_equals(&addr->address, &session->ipv4.local.address));

	log_debug("Deleted %d session, related to an static BIB", s);
	spin_unlock_bh(&table->session_table_lock);
	return 0;
}

/**
 * Helper of the set_*_timer functions. Safely updates "session"->dying_time and moves it from its
 * original location to the end of "list".
 */
void sessiondb_update_timer(struct session_entry *session, timer_type type, __u64 ttl)
{
	struct list_head *list;

	switch (type) {
	case TIMERTYPE_UDP:
		list = &sessions_udp;
		break;

	case TIMERTYPE_TCP_EST:
		list = &sessions_tcp_est;
		break;

	case TIMERTYPE_TCP_TRANS:
		list = &sessions_tcp_trans;
		break;

	case TIMERTYPE_TCP_SYN:
		list = &sessions_syn;
		break;

	case TIMERTYPE_ICMP:
		list = &sessions_icmp;
		break;

	default:
		log_crit(ERR_UNKNOWN_ERROR, "Unknown timer type to set the update timer");
		return;
		break;
	}

	session->dying_time = jiffies + ttl;

	list_del(&session->expire_list_hook);
	list_add(&session->expire_list_hook, list->prev);

	if (!timer_pending(&expire_timer) || time_before(session->dying_time, expire_timer.expires)) {
		mod_timer(&expire_timer, session->dying_time);
		log_debug("The session cleaning timer will awake in %u msecs.",
				jiffies_to_msecs(expire_timer.expires - jiffies));
	}
}

