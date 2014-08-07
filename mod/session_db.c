#include "nat64/mod/session_db.h"

#include <net/ipv6.h>
#include "nat64/comm/constants.h"
#include "nat64/mod/rbtree.h"
#include "nat64/mod/pkt_queue.h"
#include "nat64/mod/pool6.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/rfc6052.h"
#include "nat64/mod/send_packet.h"

#include "session.c"

/********************************************
 * Structures and private variables.
 ********************************************/

/**
 * Session table definition.
 * Holds red-black trees, one for each indexing need (IPv4 and IPv6).
 */
struct session_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;
	/** Number of session entries in this table. */
	u64 count;
	/**
	 * Lock to sync access. This protects both the trees and the entries, but if you only need to
	 * read the const portion of the entries, you can get away with only incresing their reference
	 * counter.
	 */
	spinlock_t lock;
};

/** The session table for UDP conversations. */
static struct session_table session_table_udp;
/** The session table for TCP connections. */
static struct session_table session_table_tcp;
/** The session table for ICMP conversations. */
static struct session_table session_table_icmp;

/** Killer of sessions whose expiration date was initialized using "config".ttl.udp. */
static struct expire_timer expirer_udp;
/** Killer of sessions whose expiration date was initialized using "config".ttl.tcp_est. */
static struct expire_timer expirer_tcp_est;
/** Killer of sessions whose expiration date was initialized using "config".ttl.tcp_trans. */
static struct expire_timer expirer_tcp_trans;
/** Killer of sessions whose expiration date was initialized using "config".ttl.icmp. */
static struct expire_timer expirer_icmp;
/** Killer of sessions whose expiration date was initialized using "TCP_INCOMING_SYN". */
static struct expire_timer expirer_syn;

/** Current valid configuration for the Session DB module. */
static struct sessiondb_config *config;

static char* EXPIRER_NAMES[] = { "UDP", "ICMP", "TCP_EST", "TCP_TRANS", "TCP_SYN" };

/********************************************
 * Private (helper) functions.
 ********************************************/

/**
 * One-liner to get the session table corresponding to the "l4_proto" protocol.
 *
 * Doesn't care about spinlocks.
 */
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
	}

	WARN(true, "Unsupported transport protocol: %u.", l4_proto);
	return -EINVAL;
}

/**
 * Fills "pair" with "tuple"'s contents.
 *
 * Doesn't care about spinlocks.
 */
static void tuple_to_ipv6_pair(struct tuple *tuple, struct ipv6_pair *pair)
{
	pair->remote.address = tuple->src.addr.ipv6;
	pair->remote.l4_id = tuple->src.l4_id;
	pair->local.address = tuple->dst.addr.ipv6;
	pair->local.l4_id = tuple->dst.l4_id;
}

/**
 * Fills "pair" with "tuple"'s contents.
 *
 * Doesn't care about spinlocks.
 */
static void tuple_to_ipv4_pair(struct tuple *tuple, struct ipv4_pair *pair)
{
	pair->remote.address = tuple->src.addr.ipv4;
	pair->remote.l4_id = tuple->src.l4_id;
	pair->local.address = tuple->dst.addr.ipv4;
	pair->local.l4_id = tuple->dst.l4_id;
}

/**
 * Returns a positive integer if session.ipv6 < pair.
 * Returns a negative integer if session.ipv6 > pair.
 * Returns zero if session.ipv6 == pair.
 *
 * Doesn't care about spinlocks.
 */
static int compare_full6(const struct session_entry *session, const struct ipv6_pair *pair)
{
	int gap;

	gap = ipv6_addr_cmp(&pair->local.address, &session->ipv6.local.address);
	if (gap != 0)
		return gap;

	gap = ipv6_addr_cmp(&pair->remote.address, &session->ipv6.remote.address);
	if (gap != 0)
		return gap;

	gap = pair->local.l4_id - session->ipv6.local.l4_id;
	if (gap != 0)
		return gap;

	gap = pair->remote.l4_id - session->ipv6.remote.l4_id;
	return gap;
}

/**
 * Returns a positive integer if session.ipv4.local < addr.
 * Returns a negative integer if session.ipv4.local > addr.
 * Returns zero if session.ipv4.local == addr.
 *
 * Doesn't care about spinlocks.
 */
static int compare_local4(const struct session_entry *session,
		const struct ipv4_tuple_address *addr)
{
	int gap;

	gap = ipv4_addr_cmp(&addr->address, &session->ipv4.local.address);
	if (gap != 0)
		return gap;

	gap = addr->l4_id - session->ipv4.local.l4_id;
	return gap;
}

/**
 * Returns a positive integer if session.ipv4 < pair.
 * Returns a negative integer if session.ipv4 > pair.
 * Returns zero if session.ipv4 == pair.
 *
 * It excludes remote layer-4 IDs from the comparison. See sessiondb_allow() to find out why.
 *
 * Doesn't care about spinlocks.
 */
static int compare_addrs4(const struct session_entry *session, const struct ipv4_pair *pair)
{
	int gap;

	gap = compare_local4(session, &pair->local);
	if (gap != 0)
		return gap;

	gap = ipv4_addr_cmp(&pair->remote.address, &session->ipv4.remote.address);
	return gap;
}

/**
 * Returns a positive integer if session.ipv4 < pair.
 * Returns a negative integer if session.ipv4 > pair.
 * Returns zero if session.ipv4 == pair.
 *
 * Doesn't care about spinlocks.
 */
static int compare_full4(const struct session_entry *session, const struct ipv4_pair *pair)
{
	int gap;

	gap = compare_addrs4(session, pair);
	if (gap != 0)
		return gap;

	gap = pair->remote.l4_id - session->ipv4.remote.l4_id;
	return gap;
}

/**
 * Returns a positive integer if session.ipv4.local < addr.
 * Returns a negative integer if session.ipv4.local > addr.
 * Returns zero if session.ipv4.local == addr.
 *
 * Doesn't care about spinlocks.
 */
static int compare_local_addr4(const struct session_entry *session, const struct in_addr *addr)
{
	return ipv4_addr_cmp(addr, &session->ipv4.local.address);
}

/**
 * Sends a probe packet to "session"'s IPv6 endpoint, to trigger a confirmation ACK if the
 * connection is still alive.
 *
 * From RFC 6146 page 30.
 *
 * @param[in] session the established session that has been inactive for too long.
 *
 * Doesn't care about spinlocks, but "session" might.
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
		log_debug("Could now allocate a probe packet.");
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

	skb_clear_cb(skb);
	error = ip6_local_out(skb);
	if (error) {
		log_debug("The kernel's packet dispatch function returned errcode %d.", error);
		goto fail;
	}

	return;

fail:
	log_debug("Looks like a TCP connection will break or remain idle forever somewhere...");
}

/**
 * Removes all of this database's references towards "session", and drops its refcount accordingly.
 *
 * The only thing it doesn't do is decrement count of "session"'s table! I do that outside because
 * I always want to add up and report that number.
 *
 * @return number of sessions removed from the database. This is always 1, because I have no way to
 *		know if the removal failed (and it shouldn't be possible anyway).
 *
 * "table"'s spinlock must already be held.
 */
static int remove(struct session_entry *session, struct session_table *table)
{
	if (!RB_EMPTY_NODE(&session->tree6_hook))
		rb_erase(&session->tree6_hook, &table->tree6);
	if (!RB_EMPTY_NODE(&session->tree4_hook))
		rb_erase(&session->tree4_hook, &table->tree4);

	list_del(&session->expire_list_hook);
	session->expirer = NULL;
	session_return(session);
	return 1;
}

/**
 * Wrapper for mod_timer().
 *
 * Not holding a spinlock is desirable for performance reasons (mod_timer() syncs itself).
 */
static void schedule_timer(struct timer_list *timer, unsigned long next_time, char *expirer_name)
{
	unsigned long min_next = jiffies + MIN_TIMER_SLEEP;

	if (time_before(next_time, min_next))
		next_time = min_next;

	mod_timer(timer, next_time);
	log_debug("%s timer will awake in %u msecs.", expirer_name,
			jiffies_to_msecs(timer->expires - jiffies));
}

/**
 * Returns the configured timeout for all of "expirer"'s sessions.
 *
 * Doesn't care about spinlocks.
 */
static unsigned long get_timeout(struct expire_timer *expirer)
{
	unsigned long timeout;

	if (expirer == &expirer_syn)
		return msecs_to_jiffies(1000 * TCP_INCOMING_SYN);

	rcu_read_lock_bh();
	timeout = *(expirer->timeout_offset + (__u64 *) rcu_dereference_bh(config));
	rcu_read_unlock_bh();

	return timeout;
}

int sessiondb_get_timeout(struct session_entry *session, unsigned long *result)
{
	if (!session->expirer) {
		log_debug("The session entry doesn't have an expirer");
		return -EINVAL;
	}

	*result = get_timeout(session->expirer);
	return 0;
}

/**
 * Handles "session"'s expiration, assuming it's a TCP session.
 *
 * Because of the state machine, the expiration of a TCP session sometimes does not immediately
 * trigger its destruction. That's why this is a separate function. If "session" should not be
 * destroyed, this will update and relocate it.
 *
 * @return the number of sessions actually removed from the DB (0 or 1).
 *
 * session's table's spinlock must already be held.
 */
static int session_tcp_expire(struct session_entry *session, struct list_head *tcp_timeouts,
		struct list_head *probes)
{
	struct session_entry *clone;

	switch (session->state) {
	case V4_INIT:
		clone = session_clone(session);
		if (clone)
			list_add(&clone->expire_list_hook, tcp_timeouts);

		session->state = CLOSED;

		return remove(session, &session_table_tcp);

	case ESTABLISHED:
		clone = session_clone(session);
		if (clone)
			list_add(&clone->expire_list_hook, probes);

		session->state = TRANS;
		session->update_time = jiffies;

		list_del(&session->expire_list_hook);
		list_add_tail(&session->expire_list_hook, &expirer_tcp_trans.sessions);
		session->expirer = &expirer_tcp_trans;

		return 0;

	case V6_INIT:
	case V4_FIN_RCV:
	case V6_FIN_RCV:
	case V4_FIN_V6_FIN_RCV:
	case TRANS:
		session->state = CLOSED;
		return remove(session, &session_table_tcp);

	case CLOSED:
		/* Closed sessions are not supposed to be stored, so this is an error. */
		WARN(true, "Closed state found; removing session entry.");
		return remove(session, &session_table_tcp);
	}

	WARN(true, "Unknown state found (%d); removing session entry.", session->state);
	return remove(session, &session_table_tcp);
}

/**
 * Called once in a while to kick off the scheduled expired sessions massacre.
 *
 * In that sense, it's a public function, so it requires spinlocks to NOT be held.
 */
static void cleaner_timer(unsigned long param)
{
	struct expire_timer *expirer = (struct expire_timer *) param;
	struct list_head *current_hook, *next_hook;
	struct list_head probes, tcp_timeouts;
	struct session_entry *session;
	unsigned long timeout;
	unsigned long session_update_time = 0;
	unsigned int s = 0;
	bool schedule_tcp_trans = false;

	log_debug("===============================================");
	log_debug("Deleting expired sessions...");
	log_debug("Cleaner name: %s", expirer->name);

	timeout = get_timeout(expirer);
	INIT_LIST_HEAD(&probes);
	INIT_LIST_HEAD(&tcp_timeouts);

	spin_lock_bh(&expirer->table->lock);

	list_for_each_safe(current_hook, next_hook, &expirer->sessions) {
		session = list_entry(current_hook, struct session_entry, expire_list_hook);

		if (time_before(jiffies, session->update_time + timeout)) {
			/* "list" is sorted by expiration date, so stop on the first unexpired session. */
			session_update_time = session->update_time + timeout;
			break;
		}

		if (session->l4_proto != L4PROTO_TCP)
			s += remove(session, expirer->table);
		else 
			s += session_tcp_expire(session, &tcp_timeouts, &probes);
		

	}

	expirer->table->count -= s;
	schedule_tcp_trans = !timer_pending(&expirer_tcp_trans.timer) &&
			!list_empty(&expirer_tcp_trans.sessions) && (expirer != &expirer_tcp_trans);
	spin_unlock_bh(&expirer->table->lock);

	if (schedule_tcp_trans)
		schedule_timer(&expirer_tcp_trans.timer, jiffies + get_timeout(&expirer_tcp_trans), expirer_tcp_trans.name);

	if (session_update_time)
		schedule_timer(&expirer->timer, session_update_time, expirer->name);

	list_for_each_safe(current_hook, next_hook, &tcp_timeouts) {
		session = list_entry(current_hook, struct session_entry, expire_list_hook);
		pktqueue_send(session);
		session_return(session);
	}

	list_for_each_safe(current_hook, next_hook, &probes) {
		session = list_entry(current_hook, struct session_entry, expire_list_hook);
		send_probe_packet(session);
		session_return(session);
	}

	log_debug("Deleted %u sessions.", s);
}

/*******************************
 * Public functions.
 *******************************/

/**
 * Auxiliar for sessiondb_init(). Encapsulates initialization of an expire_timer structure.
 *
 * Doesn't care about spinlocks (initialization code doesn't share threads).
 */
static void init_expire_timer(struct expire_timer *expirer, struct session_table *table,
		size_t timeout_offset, char *expirer_name)
{
	init_timer(&expirer->timer);
	expirer->timer.function = cleaner_timer;
	expirer->timer.expires = 0;
	expirer->timer.data = (unsigned long) expirer;

	INIT_LIST_HEAD(&expirer->sessions);
	expirer->table = table;
	expirer->timeout_offset = timeout_offset / sizeof(__u64);
	expirer->name = expirer_name;
}

int sessiondb_init(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;
	int error;

	error = session_init();
	if (error)
		return error;

	config = kmalloc(sizeof(*config), GFP_ATOMIC);
	if (!config) {
		log_debug("Could not allocate memory to store the session DB config.");
		return -ENOMEM;
	}

	config->ttl.udp = msecs_to_jiffies(1000 * UDP_DEFAULT);
	config->ttl.icmp = msecs_to_jiffies(1000 * ICMP_DEFAULT);
	config->ttl.tcp_est = msecs_to_jiffies(1000 * TCP_EST);
	config->ttl.tcp_trans = msecs_to_jiffies(1000 * TCP_TRANS);

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		tables[i]->tree6 = RB_ROOT;
		tables[i]->tree4 = RB_ROOT;
		tables[i]->count = 0;
		spin_lock_init(&tables[i]->lock);
	}

	init_expire_timer(&expirer_udp, &session_table_udp,
			offsetof(struct sessiondb_config, ttl.udp), EXPIRER_NAMES[0]);
	init_expire_timer(&expirer_icmp, &session_table_icmp,
			offsetof(struct sessiondb_config, ttl.icmp), EXPIRER_NAMES[1]);
	init_expire_timer(&expirer_tcp_est, &session_table_tcp,
			offsetof(struct sessiondb_config, ttl.tcp_est), EXPIRER_NAMES[2]);
	init_expire_timer(&expirer_tcp_trans, &session_table_tcp,
			offsetof(struct sessiondb_config, ttl.tcp_trans), EXPIRER_NAMES[3]);
	init_expire_timer(&expirer_syn, &session_table_tcp, 0, EXPIRER_NAMES[4]);

	return 0;
}

/**
 * Auxiliar for sessiondb_destroy(). Wraps the destruction of a session, exposing an API the rbtree
 * module wants.
 *
 * Doesn't care about spinlocks (destructor code doesn't share threads).
 */
static void session_destroy_aux(struct rb_node *node)
{
	kmem_cache_free(entry_cache, rb_entry(node, struct session_entry, tree6_hook));
}

void sessiondb_destroy(void)
{
	struct session_table *tables[] = { &session_table_udp, &session_table_tcp,
			&session_table_icmp };
	int i;

	del_timer_sync(&expirer_udp.timer);
	del_timer_sync(&expirer_tcp_est.timer);
	del_timer_sync(&expirer_tcp_trans.timer);
	del_timer_sync(&expirer_syn.timer);
	del_timer_sync(&expirer_icmp.timer);

	log_debug("Emptying the session tables...");
	/*
	 * The values need to be released only in one of the trees
	 * because both trees point to the same values.
	 */
	for (i = 0; i < ARRAY_SIZE(tables); i++)
		rbtree_clear(&tables[i]->tree6, session_destroy_aux);

	session_destroy();
}

int sessiondb_clone_config(struct sessiondb_config *clone)
{
	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	rcu_read_unlock_bh();
	return 0;
}

int sessiondb_set_config(enum sessiondb_type type, size_t size, void *value)
{
	struct sessiondb_config *tmp_config;
	struct sessiondb_config *old_config;
	struct expire_timer *expirer;
	__u64 value64;
	__u32 max_u32 = 0xFFFFFFFFL; /* Max value in milliseconds */

	if (size != sizeof(__u64)) {
		log_err("Expected an 8-byte integer, got %zu bytes.", size);
		return -EINVAL;
	}

	value64 = *((__u64 *) value);
	if (value64 > max_u32) {
		log_err("Expected a timeout less than %u seconds", max_u32 / 1000);
		return -EINVAL;
	}

	value64 = msecs_to_jiffies(value64);

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	switch (type) {
	case UDP_TIMEOUT:
		if (value64 < msecs_to_jiffies(1000 * UDP_MIN)) {
			log_err("The UDP timeout must be at least %u seconds.", UDP_MIN);
			goto fail;
		}
		tmp_config->ttl.udp = value64;
		expirer = &expirer_udp;
		break;
	case ICMP_TIMEOUT:
		tmp_config->ttl.icmp = value64;
		expirer = &expirer_icmp;
		break;
	case TCP_EST_TIMEOUT:
		if (value64 < msecs_to_jiffies(1000 * TCP_EST)) {
			log_err("The TCP est timeout must be at least %u seconds.", TCP_EST);
			goto fail;
		}
		tmp_config->ttl.tcp_est = value64;
		expirer = &expirer_tcp_est;
		break;
	case TCP_TRANS_TIMEOUT:
		if (value64 < msecs_to_jiffies(1000 * TCP_TRANS)) {
			log_err("The TCP trans timeout must be at least %u seconds.", TCP_TRANS);
			goto fail;
		}
		tmp_config->ttl.tcp_trans = value64;
		expirer = &expirer_tcp_trans;
		break;
	default:
		log_err("Unknown config type for the 'session database' module: %u", type);
		goto fail;
	}

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();
	kfree(old_config);
	commit_timer(expirer);
	return 0;

fail:
	kfree(tmp_config);
	return -EINVAL;
}

/**
 * Returns in "result" the session entry from the "l4_proto" table that corresponds to the "pair"
 * IPv4 addresses.
 */
static int sessiondb_get_by_ipv4(struct ipv4_pair *pair, l4_protocol l4_proto,
		struct session_entry **result)
{
	struct session_table *table;
	int error;

	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	*result = rbtree_find(pair, &table->tree4, compare_full4, struct session_entry, tree4_hook);
	if (*result)
		session_get(*result);
	spin_unlock_bh(&table->lock);

	return (*result) ? 0 : -ENOENT;
}

/**
 * Returns in "result" the session entry from the "l4_proto" table that corresponds to the "pair"
 * IPv6 addresses.
 */
static int sessiondb_get_by_ipv6(struct ipv6_pair *pair, l4_protocol l4_proto,
		struct session_entry **result)
{
	struct session_table *table;
	int error;

	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	*result = rbtree_find(pair, &table->tree6, compare_full6, struct session_entry, tree6_hook);
	if (*result)
		session_get(*result);
	spin_unlock_bh(&table->lock);

	return (*result) ? 0 : -ENOENT;
}

int sessiondb_get(struct tuple *tuple, struct session_entry **result)
{
	struct ipv6_pair pair6;
	struct ipv4_pair pair4;

	if (WARN(!tuple, "There's no session entry mapped to NULL."))
		return -EINVAL;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		tuple_to_ipv6_pair(tuple, &pair6);
		return sessiondb_get_by_ipv6(&pair6, tuple->l4_proto, result);
	case L3PROTO_IPV4:
		tuple_to_ipv4_pair(tuple, &pair4);
		return sessiondb_get_by_ipv4(&pair4, tuple->l4_proto, result);
	}

	WARN(true, "Unsupported network protocol: %u.", tuple->l3_proto);
	return -EINVAL;
}

bool sessiondb_allow(struct tuple *tuple)
{
	struct session_table *table;
	struct session_entry *session;
	struct ipv4_pair tuple_pair;
	int error;
	bool result;

	/* Sanity */
	if (WARN(!tuple, "Cannot extract addresses from NULL."))
		return false;
	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	tuple_to_ipv4_pair(tuple, &tuple_pair);

	spin_lock_bh(&table->lock);
	session = rbtree_find(&tuple_pair, &table->tree4, compare_addrs4, struct session_entry,
			tree4_hook);
	result = session ? true : false;
	spin_unlock_bh(&table->lock);

	return result;
}

static bool is_set(const struct ipv6_tuple_address *addr)
{
	return addr->address.s6_addr32[0]
			|| addr->address.s6_addr32[1]
			|| addr->address.s6_addr32[2]
			|| addr->address.s6_addr32[3]
			|| addr->l4_id;
}

int sessiondb_add(struct session_entry *session)
{
	struct session_table *table;
	struct rb_node *parent, **node;
	int error;

	/* Sanity */
	if (WARN(!session, "Cannot insert NULL to a session table."))
		return -EINVAL;
	error = get_session_table(session->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	spin_lock_bh(&table->lock);

	error = rbtree_add(session, ipv6, &table->tree6, compare_full6, struct session_entry,
			tree6_hook);
	if (error) {
		spin_unlock_bh(&table->lock);
		return -EEXIST;
	}

	rbtree_find_node(&session->ipv4, &table->tree4, compare_full4, struct session_entry,
			tree4_hook, parent, node);
	if (*node) {
		/*
		 * This can happen on Simultaneous Open (SO) of TCP connections.
		 * An incomplete dummy session was inserted to the database (we didn't have the remote
		 * IPv6 address at the time), and now we have to replace it with the full version.
		 */
		struct session_entry *other;
		other = rb_entry(*node, struct session_entry, tree4_hook);

		if (WARN(is_set(&other->ipv6.remote), "IPv6 index worked, IPv4 index didn't."))
			goto index_trainwreck; /* No actually a SO; this should never happen. */

		pktqueue_remove(other); /* Not sure what to make out it if this fails. */

		table->count -= remove(other, table);
		error = rbtree_add(session, ipv4, &table->tree4, compare_full4, struct session_entry,
				tree4_hook);
		if (WARN(error, "Just removed the conflicting session, insertion still failed."))
			goto index_trainwreck;

	} else {
		rb_link_node(&session->tree4_hook, parent, node);
		rb_insert_color(&session->tree4_hook, &table->tree4);
	}

	session_get(session); /* We have 2 indexes, but really they count as one. */
	table->count++;
	spin_unlock_bh(&table->lock);
	return 0;

index_trainwreck:
	rb_erase(&session->tree6_hook, &table->tree6);
	spin_unlock_bh(&table->lock);
	return -EEXIST;
}

int sessiondb_for_each(l4_protocol l4_proto, int (*func)(struct session_entry *, void *), void *arg)
{
	struct session_table *table;
	struct rb_node *node;
	int error;

	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	for (node = rb_first(&table->tree4); node && !error; node = rb_next(node)) {
		error = func(rb_entry(node, struct session_entry, tree4_hook), arg);
	}

	spin_unlock_bh(&table->lock);
	return error;
}

/**
 * See the function of the same name from the BIB DB module for comments on this.
 *
 * Requires "table"'s spinlock to already be held.
 */
static struct rb_node *find_next_chunk(struct session_table *table,
		struct ipv4_tuple_address *addr, bool starting)
{
	struct rb_node **node, *parent;
	struct session_entry *session;

	if (starting)
		return rb_first(&table->tree4);

	rbtree_find_node(addr, &table->tree4, compare_local4, struct session_entry, tree4_hook, parent,
			node);
	if (*node)
		return rb_next(*node);

	session = rb_entry(parent, struct session_entry, tree4_hook);
	return (compare_local4(session, addr) < 0) ? parent : rb_next(parent);
}

int sessiondb_iterate_by_ipv4(l4_protocol l4_proto, struct ipv4_tuple_address *addr, bool starting,
		int (*func)(struct session_entry *, void *), void *arg)
{
	struct session_table *table;
	struct rb_node *node;
	int error;

	if (WARN(!addr, "The IPv4 address is NULL."))
		return -EINVAL;
	error = get_session_table(l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	for (node = find_next_chunk(table, addr, starting); node && !error; node = rb_next(node)) {
		error = func(rb_entry(node, struct session_entry, tree4_hook), arg);
	}

	spin_unlock_bh(&table->lock);
	return error;
}

int sessiondb_count(l4_protocol proto, __u64 *result)
{
	struct session_table *table;
	int error;

	error = get_session_table(proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	*result = table->count;
	spin_unlock_bh(&table->lock);
	return 0;
}

int sessiondb_get_or_create_ipv6(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in_addr ipv4_dst;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	struct rb_node **node, *parent;
	struct session_table *table;
	int error;

	if (WARN(!tuple, "There's no session entry mapped to NULL."))
		return -EINVAL;

	tuple_to_ipv6_pair(tuple, &pair6);

	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);
	rbtree_find_node(&pair6, &table->tree6, compare_full6, struct session_entry, tree6_hook,
			parent, node);
	if (*node) {
		*session = rb_entry(*node, struct session_entry, tree6_hook);
		session_get(*session);
		goto end;
	}
	/* The entry doesn't exist, so try to create it. */

	/* Translate address from IPv6 to IPv4 */
	error = pool6_get(&tuple->dst.addr.ipv6, &prefix);
	if (error) {
		log_debug("Errcode %d while obtaining %pI6c's prefix.", error, &tuple->dst.addr.ipv6);
		goto end;
	}

	error = addr_6to4(&tuple->dst.addr.ipv6, &prefix, &ipv4_dst);
	if (error) {
		log_debug("Error code %d while translating the packet's address.", error);
		goto end;
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
	*session = session_create(&pair4, &pair6, tuple->l4_proto, bib); /* refcounter = 1*/
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		error = -ENOMEM;
		goto end;
	}

	/* Add it to the database. */
	rb_link_node(&(*session)->tree6_hook, parent, node);
	rb_insert_color(&(*session)->tree6_hook, &table->tree6);

	error = rbtree_add(*session, ipv4, &table->tree4, compare_full4, struct session_entry,
			tree4_hook);
	if (error) {
		WARN(true, "The session entry could be indexed by IPv6, but not by IPv4.");
		rb_erase(&(*session)->tree6_hook, &table->tree6);
		session_return(*session);
		goto end;
	}

	session_get(*session); /* refcounter = 2 (the DB's and the one we're about to return) */
	table->count++;
	/* Fall through. */

end:
	spin_unlock_bh(&table->lock);
	return error;
}


int sessiondb_get_or_create_ipv4(struct tuple *tuple, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct in6_addr ipv6_src;
	struct ipv4_pair pair4;
	struct ipv6_pair pair6;
	struct rb_node **node, *parent;
	struct session_table *table;
	int error;

	if (WARN(!tuple, "There's no session entry mapped to NULL."))
		return -EINVAL;

	tuple_to_ipv4_pair(tuple, &pair4);

	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);
	rbtree_find_node(&pair4, &table->tree4, compare_full4, struct session_entry, tree4_hook,
			parent, node);
	if (*node) {
		*session = rb_entry(*node, struct session_entry, tree4_hook);
		session_get(*session);
		goto end;
	}
	/* The entry doesn't exist, so try to create it. */

	/* Translate address from IPv4 to IPv6 */
	error = pool6_peek(&prefix);
	if (error)
		goto end;

	error = addr_4to6(&tuple->src.addr.ipv4, &prefix, &ipv6_src);
	if (error) {
		log_debug("Error code %d while translating the packet's address.", error);
		goto end;
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
	*session = session_create(&pair4, &pair6, tuple->l4_proto, bib); /* refcounter = 1 */
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		error = -ENOMEM;
		goto end;
	}

	/* Add it to the database. */
	rb_link_node(&(*session)->tree4_hook, parent, node);
	rb_insert_color(&(*session)->tree4_hook, &table->tree4);

	error = rbtree_add(*session, ipv6, &table->tree6, compare_full6, struct session_entry,
			tree6_hook);
	if (error) {
		WARN(true, "The session entry could be indexed by IPv4, but not by IPv6.");
		rb_erase(&(*session)->tree4_hook, &table->tree4);
		session_return(*session);
		goto end;
	}

	session_get(*session); /* refcounter = 2 (the DB's and the one we're about to return) */
	table->count++;
	/* Fall through. */

end:
	spin_unlock_bh(&table->lock);
	return error;
}

int sessiondb_delete_by_bib(struct bib_entry *bib)
{
	struct session_table *table;
	struct session_entry *root_session, *session;
	struct rb_node *node;
	int error;
	int s = 0;

	/* Sanitize */
	error = get_session_table(bib->l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);

	/* Find the top-most node in the tree whose IPv4 address is addr. */
	root_session = rbtree_find(&bib->ipv4, &table->tree4, compare_local4, struct session_entry,
			tree4_hook);
	if (!root_session)
		goto success; /* "Successfully" deleted zero entries. */

	/* Keep moving left deleting sessions until the local address changes. */
	node = rb_prev(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		if (compare_local4(session, &bib->ipv4) != 0)
			break;
		s += remove(session, table);

		node = rb_prev(&root_session->tree4_hook);
	}

	/* Keep moving right deleting sessions until the local address changes. */
	node = rb_next(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		if (compare_local4(session, &bib->ipv4) != 0)
			break;
		s += remove(session, table);

		node = rb_next(&root_session->tree4_hook);
	}

	s += remove(root_session, table);
	table->count -= s;
	/* Fall through. */

success:
	spin_unlock_bh(&table->lock);
	log_debug("Deleted %d sessions.", s);
	return 0;
}

/**
 * Deletes the sessions from the "table" table whose local IPv4 address is "addr".
 * This function is awfully similar to sessiondb_delete_by_bib(). See that for more comments.
 */
static int delete_sessions_by_ipv4(struct session_table *table, struct in_addr *addr)
{
	struct session_entry *root_session, *session;
	struct rb_node *node;
	int s = 0;

	spin_lock_bh(&table->lock);

	root_session = rbtree_find(addr, &table->tree4, compare_local_addr4, struct session_entry,
			tree4_hook);
	if (!root_session)
		goto success;

	node = rb_prev(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		if (compare_local_addr4(session, addr) != 0)
			break;
		s += remove(session, table);

		node = rb_prev(&root_session->tree4_hook);
	}

	node = rb_next(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		if (compare_local_addr4(session, addr) != 0)
			break;
		s += remove(session, table);

		node = rb_next(&root_session->tree4_hook);
	}

	s += remove(root_session, table);
	table->count -= s;
	/* Fall through. */

success:
	spin_unlock_bh(&table->lock);
	log_debug("Deleted %d sessions.", s);
	return 0;
}

int sessiondb_delete_by_ipv4(struct in_addr *addr4)
{
	if (WARN(!addr4, "The IPv4 address is NULL"))
		return -EINVAL;

	delete_sessions_by_ipv4(&session_table_tcp, addr4);
	delete_sessions_by_ipv4(&session_table_icmp, addr4);
	delete_sessions_by_ipv4(&session_table_udp, addr4);

	return 0;
}

/**
 * Helper of the set_*_timer functions. Safely updates "session"->dying_time using "ttl" and moves
 * it from its original location to the end of "list".
 */
static struct expire_timer *set_timer(struct session_entry *session, struct expire_timer *expirer)
{
	struct expire_timer *result;

	spin_lock_bh(&expirer->table->lock);

	session->update_time = jiffies;
	list_del(&session->expire_list_hook);
	list_add_tail(&session->expire_list_hook, &expirer->sessions);
	session->expirer = expirer;

	/*
	 * The new session is always going to expire last.
	 * So if the timer is already set, there should be no reason to edit it.
	 */
	result = timer_pending(&expirer->timer) ? NULL : expirer;

	spin_unlock_bh(&expirer->table->lock);
	return result;
}

struct expire_timer *set_udp_timer(struct session_entry *session)
{
	return set_timer(session, &expirer_udp);
}

struct expire_timer *set_tcp_est_timer(struct session_entry *session)
{
	return set_timer(session, &expirer_tcp_est);
}

struct expire_timer *set_tcp_trans_timer(struct session_entry *session)
{
	return set_timer(session, &expirer_tcp_trans);
}

struct expire_timer *set_icmp_timer(struct session_entry *session)
{
	return set_timer(session, &expirer_icmp);
}

struct expire_timer *set_syn_timer(struct session_entry *session)
{
	return set_timer(session, &expirer_syn);
}

void commit_timer(struct expire_timer *expirer)
{
	if (expirer)
		schedule_timer(&expirer->timer, jiffies + get_timeout(expirer), expirer->name);
}

/**
 * Returns 1 if "session"->ipv6.local.address contains "prefix".
 * otherwise returns zero.
 *
 * Doesn't care about spinlocks.
 */
static int sessiondb_ipv6_prefix_equal(struct session_entry *session, struct ipv6_prefix *prefix)
{
	return ipv6_prefix_equal(&prefix->address, &session->ipv6.local.address, prefix->len);
}

/**
 * Used in delete_sessions_by_ipv6_prefix when is searching in the Session tree6,
 * returns zero if "session"->ipv6.local.address is equals to "prefix" or contains the "prefix".
 * Otherwise return the gap of the comparison result.
 */
static int compare_local_prefix6(struct session_entry *session, struct ipv6_prefix *prefix) {
	int gap;

	gap = ipv6_addr_cmp(&prefix->address, &session->ipv6.local.address);
	if (gap == 0)
		return 0;

	if (sessiondb_ipv6_prefix_equal(session, prefix))
		return 0;

	return gap;
}

/**
 * Deletes the sessions from the "table" table whose local IPv6 address contains "prefix".
 * This function is awfully similar to sessiondb_delete_by_bib(). See that for more comments.
 */
static int delete_sessions_by_ipv6_prefix(struct session_table *table, struct ipv6_prefix *prefix)
{
	struct session_entry *root_session, *session;
	struct rb_node *node;
	int s = 0;

	spin_lock_bh(&table->lock);

	root_session = rbtree_find(prefix, &table->tree6, compare_local_prefix6, struct session_entry,
			tree6_hook);
	if (!root_session)
		goto success;

	node = rb_prev(&root_session->tree6_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree6_hook);
		node = rb_prev(&session->tree6_hook);

		if (!sessiondb_ipv6_prefix_equal(session, prefix))
			break;
		s += remove(session, table);
	}

	node = rb_next(&root_session->tree6_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree6_hook);
		node = rb_next(&session->tree6_hook);

		if (!sessiondb_ipv6_prefix_equal(session, prefix))
			break;
		s += remove(session, table);
	}

	s += remove(root_session, table);
	table->count -= s;
	/* Fall through. */

success:
	spin_unlock_bh(&table->lock);
	log_debug("Deleted %d sessions.", s);
	return 0;
}

int sessiondb_delete_by_ipv6_prefix(struct ipv6_prefix *prefix)
{
	if (WARN(!prefix, "The IPv6 prefix is NULL"))
		return -EINVAL;

	delete_sessions_by_ipv6_prefix(&session_table_tcp, prefix);
	delete_sessions_by_ipv6_prefix(&session_table_icmp, prefix);
	delete_sessions_by_ipv6_prefix(&session_table_udp, prefix);

	return 0;
}

static int flush_aux(struct session_table *table)
{
	struct session_entry *root_session, *session;
	struct rb_node *node;
	int s = 0;

	spin_lock_bh(&table->lock);

	node = (&table->tree4)->rb_node;
	if (!node)
		goto success;

	root_session = rb_entry(node, struct session_entry, tree4_hook);
	if (!root_session)
		goto success;

	node = rb_prev(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		node = rb_prev(&session->tree4_hook);
		s += remove(session, table);
	}

	node = rb_next(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		node = rb_next(&session->tree4_hook);
		s += remove(session, table);
	}

	s += remove(root_session, table);
	table->count -= s;
	/* Fall through. */

success:
	spin_unlock_bh(&table->lock);
	log_debug("Deleted %d sessions.", s);
	return 0;
}

int sessiondb_flush(void)
{
	log_debug("Emptying the session tables...");
	flush_aux(&session_table_udp);
	flush_aux(&session_table_tcp);
	flush_aux(&session_table_icmp);

	return 0;
}
