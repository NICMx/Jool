#include "nat64/mod/stateful/session/db.h"

#include "nat64/common/constants.h"
#include "nat64/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateful/session/pkt_queue.h"
#include "nat64/mod/stateful/session/table4.h"
#include "nat64/mod/stateful/session/table6.h"

typedef unsigned long (*timeout_cb)(void);

struct expire_timer {
	struct list_head sessions;
	unsigned long timeout;
	bool is_established;
	fate_cb decide_fate_cb;
};

struct session_table {
	struct session_table4 *t4;
	struct session_table6 *t6;

	/** Expires this table's established sessions. */
	struct expire_timer est_timer;
	/** Expires this table's transitory sessions. */
	struct expire_timer trans_timer;

	/** Number of session entries in this table. */
	u64 count;

	bool log_changes;

	spinlock_t lock;
};

struct sessiondb {
	/** The session table for UDP conversations. */
	struct session_table udp;
	/** The session table for TCP connections. */
	struct session_table tcp;
	/** The session table for ICMP conversations. */
	struct session_table icmp;
	/** Packet storage for simultaneous open of TCP connections. */
	struct pktqueue *pkt_queue;

	struct kref refs;
};

/**
 * Yes, this is private. If you think you need to kref_get outside of the
 * database spinlock, then I need you to sit down and think about it for a
 * while.
 *
 * It is buggy to run kref_get() at the same time as the last kref_put().
 * (See the kernel's kref.txt file.)
 *
 * Sessions managed by the session database currently handle this by keeping a
 * reference and by wrapping all existing session_get()s inside of database
 * functions protected by the spinlock.
 * The database's own reference prevents user kref_put()s from being the last
 * ones, as long as the session remain in the database.
 * When the session is detached from the database, the fact that this function
 * is private prevents any further session_get()s.
 *
 * Other databases (such as the pktqueue ones) do not currently share sessions
 * with other code so they don't need this function. (They can get away with
 * the kref_init() in session_create().)
 */
static void session_get(struct session_entry *session)
{
	kref_get(&session->refs);
}

/**
 * One-liner to get the session table corresponding to the @proto protocol.
 */
static struct session_table *get_table(struct sessiondb *db, l4_protocol proto)
{
	switch (proto) {
	case L4PROTO_UDP:
		return &db->udp;
	case L4PROTO_TCP:
		return &db->tcp;
	case L4PROTO_ICMP:
		return &db->icmp;
	case L4PROTO_OTHER:
		break;
	}

	WARN(true, "Unsupported transport protocol: %u.", proto);
	return NULL;
}

static enum session_fate just_die(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

/* TODO (final) maybe put this in some common header? */
enum session_fate tcp_expired_cb(struct session_entry *session, void *arg);

static void init_expirer(struct expire_timer *expirer, int timeout,
		bool is_established, fate_cb decide_fate_cb)
{
	INIT_LIST_HEAD(&expirer->sessions);
	expirer->timeout = msecs_to_jiffies(1000 * timeout);
	expirer->is_established = is_established;
	expirer->decide_fate_cb = decide_fate_cb;
}

static int sessiontable_init(struct session_table *table, fate_cb expired_cb,
		int est_timeout, int trans_timeout)
{
	table->t6 = st6_create();
	if (!table->t6)
		return -ENOMEM;
	table->t4 = st4_create();
	if (!table->t4) {
		st6_destroy(table->t6);
		return -ENOMEM;
	}

	init_expirer(&table->est_timer, est_timeout, true, expired_cb);
	init_expirer(&table->trans_timer, trans_timeout, false, expired_cb);

	table->count = 0;
	table->log_changes = DEFAULT_SESSION_LOGGING;
	spin_lock_init(&table->lock);

	return 0;
}

static void sessiontable_destroy(struct session_table *table)
{
	st6_destroy(table->t6);
	st4_destroy(table->t4);
}

int sessiondb_init(struct sessiondb **result)
{
	struct sessiondb *sdb;
	int error;

	sdb = wkmalloc(struct sessiondb, GFP_KERNEL);
	if (!sdb)
		goto fail0;

	error = sessiontable_init(&sdb->udp, just_die, UDP_DEFAULT, 0);
	if (error)
		goto fail1;
	error = sessiontable_init(&sdb->tcp, tcp_expired_cb, TCP_EST, TCP_TRANS);
	if (error)
		goto fail2;
	error = sessiontable_init(&sdb->icmp, just_die, ICMP_DEFAULT, 0);
	if (error)
		goto fail3;

	sdb->pkt_queue = pktqueue_create();
	if (!sdb->pkt_queue)
		goto fail4;

	kref_init(&sdb->refs);

	*result = sdb;
	return 0;

fail4:
	sessiontable_destroy(&sdb->icmp);
fail3:
	sessiontable_destroy(&sdb->tcp);
fail2:
	sessiontable_destroy(&sdb->udp);
fail1:
	wkfree(struct sessiondb, sdb);
fail0:
	return -ENOMEM;
}

void sessiondb_get(struct sessiondb *db)
{
	kref_get(&db->refs);
}

static void release(struct kref *refcounter)
{
	struct sessiondb *db;
	db = container_of(refcounter, typeof(*db), refs);

	log_debug("Emptying the session tables...");

	sessiontable_destroy(&db->udp);
	sessiontable_destroy(&db->tcp);
	sessiontable_destroy(&db->icmp);
	pktqueue_destroy(db->pkt_queue);

	wkfree(struct sessiondb, db);
}

void sessiondb_put(struct sessiondb *db)
{
	kref_put(&db->refs, release);
}

static void sessiontable_config_copy(struct session_table *table,
		struct session_config *config,
		enum l4_protocol proto)
{
	spin_lock_bh(&table->lock);

	switch (proto) {
	case L4PROTO_TCP:
		config->ttl.tcp_est = table->est_timer.timeout;
		config->ttl.tcp_trans = table->trans_timer.timeout;
		break;
	case L4PROTO_UDP:
		config->ttl.udp = table->est_timer.timeout;
		break;
	case L4PROTO_ICMP:
		config->ttl.icmp = table->est_timer.timeout;
		break;
	case L4PROTO_OTHER:
		break;
	}
	config->log_changes = table->log_changes;

	spin_unlock_bh(&table->lock);
}

void sessiondb_config_copy(struct sessiondb *db, struct session_config *config)
{
	sessiontable_config_copy(&db->tcp, config, L4PROTO_TCP);
	sessiontable_config_copy(&db->udp, config, L4PROTO_UDP);
	sessiontable_config_copy(&db->icmp, config, L4PROTO_ICMP);
	pktqueue_config_copy(db->pkt_queue, &config->pktqueue);
}

static void sessiontable_config_set(struct session_table *table,
		struct session_config *config,
		enum l4_protocol proto)
{
	spin_lock_bh(&table->lock);

	switch (proto) {
	case L4PROTO_TCP:
		table->est_timer.timeout = config->ttl.tcp_est;
		table->trans_timer.timeout = config->ttl.tcp_trans;
		break;
	case L4PROTO_UDP:
		table->est_timer.timeout = config->ttl.udp;
		break;
	case L4PROTO_ICMP:
		table->est_timer.timeout = config->ttl.icmp;
		break;
	case L4PROTO_OTHER:
		break;
	}
	table->log_changes = config->log_changes;

	spin_unlock_bh(&table->lock);
}

void sessiondb_config_set(struct sessiondb *db, struct session_config *config)
{
	sessiontable_config_set(&db->tcp, config, L4PROTO_TCP);
	sessiontable_config_set(&db->udp, config, L4PROTO_UDP);
	sessiontable_config_set(&db->icmp, config, L4PROTO_ICMP);
	pktqueue_config_set(db->pkt_queue, &config->pktqueue);
}

int sessiondb_find_full(struct sessiondb *db, struct tuple *tuple4,
		struct bib_entry *bib, struct session_entry **session,
		bool *allow)
{
	struct session_table *table = get_table(db, tuple4->l4_proto);
	if (!table)
		return -EINVAL;
	return st4_find_full(table->t4, tuple4, bib, session, allow);
}

int sessiondb_find_bib(struct sessiondb *db, struct tuple *tuple,
		struct bib_entry *bib)
{
	struct session_table *table = get_table(db, tuple->l4_proto);
	if (!table)
		return -EINVAL;
	return st4_find_bib(table->t4, tuple, bib);
}

/**
 * Removes all of this database's references towards "session", and drops its
 * refcount accordingly.
 *
 * "table"'s spinlock must already be held.
 */
static void rm(struct session_table *table, struct session_entry *session)
{
	st4_rm(table->t4, session);
	st6_rm(table->t6, session);
	list_del(&session->list_hook);
	table->count--;

	if (table->log_changes)
		session_log(session, "Forgot session");
}

static void queue_unsorted_session(struct expire_timer *timer,
		struct session_entry *new)
{
	struct list_head *list;
	struct list_head *cursor;
	struct session_entry *old;

	new->expirer = timer;
	list_del(&new->list_hook);

	list = &timer->sessions;
	for (cursor = list->prev; cursor != list; cursor = cursor->prev) {
		old = list_entry(cursor, struct session_entry, list_hook);
		if (old->update_time < new->update_time) {
			list_add(&new->list_hook, &old->list_hook);
			return;
		}
	}

	list_add(&new->list_hook, list);
}

static void decide_fate(fate_cb cb,
		void *cb_arg,
		struct session_table *table,
		struct session_entry *session,
		struct list_head *probes)
{
	enum session_fate fate;
	struct session_entry *tmp;

	fate = cb(session, cb_arg);
	switch (fate) {
	case FATE_TIMER_EST:
		session->update_time = jiffies;
		session->expirer = &table->est_timer;
		list_del(&session->list_hook);
		list_add_tail(&session->list_hook, &session->expirer->sessions);
		break;
	case FATE_PROBE:
		tmp = session_clone(session);
		if (tmp) {
			/*
			 * Why add a dummy session instead of the real one?
			 * Because the real session's list hook must remain
			 * attached to the database.
			 */
			list_add(&tmp->list_hook, probes);
		}
		/* Fall through. */
	case FATE_TIMER_TRANS:
		session->update_time = jiffies;
		session->expirer = &table->trans_timer;
		list_del(&session->list_hook);
		list_add_tail(&session->list_hook, &session->expirer->sessions);
		break;
	case FATE_RM:
		rm(table, session);
		break;
	case FATE_PRESERVE:
		break;
	case FATE_TIMER_EST_SLOW:
		queue_unsorted_session(&table->est_timer, session);
		break;
	case FATE_TIMER_TRANS_SLOW:
		queue_unsorted_session(&table->trans_timer, session);
		break;
	}
}

/**
 * send_probe_packet - Sends a probe packet to "session"'s IPv6 endpoint,
 * to trigger a confirmation ACK if the connection is still alive.
 *
 * From RFC 6146 page 30.
 *
 * @session: the established session that has been inactive for too long.
 *
 * Doesn't care about spinlocks, but "session" might.
 */
static void send_probe_packet(struct net *ns, struct session_entry *session)
{
	struct packet pkt;
	struct sk_buff *skb;
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
	iph->payload_len = cpu_to_be16(l4_hdr_len);
	iph->nexthdr = NEXTHDR_TCP;
	iph->hop_limit = 255;
	iph->saddr = session->dst6.l3;
	iph->daddr = session->src6.l3;

	th = tcp_hdr(skb);
	th->source = cpu_to_be16(session->dst6.l4);
	th->dest = cpu_to_be16(session->src6.l4);
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

	th->check = csum_ipv6_magic(&iph->saddr, &iph->daddr, l4_hdr_len,
			IPPROTO_TCP, csum_partial(th, l4_hdr_len, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	pkt_fill(&pkt, skb, L3PROTO_IPV6, L4PROTO_TCP, NULL, th + 1, NULL);

	if (!route6(ns, &pkt)) {
		kfree_skb(skb);
		goto fail;
	}

	/* Implicit kfree_skb(skb) here. */
#if LINUX_VERSION_AT_LEAST(4, 4, 0, 9999, 0)
	error = dst_output(ns, NULL, skb);
#else
	error = dst_output(skb);
#endif
	if (error) {
		log_debug("ip6_local_out returned errcode %d.", error);
		goto fail;
	}

	return;

fail:
	log_debug("A TCP connection will probably break.");
}

static void post_fate(struct net *ns, struct list_head *probes)
{
	struct session_entry *session;
	struct session_entry *tmp;

	list_for_each_entry_safe(session, tmp, probes, list_hook) {
		send_probe_packet(ns, session);
		session_put(session, false);
	}
}

/**
 * Note: This particular incarnation of fate_cb is not prepared to return
 * FATE_PROBE.
 */
int sessiondb_find(struct sessiondb *db, struct tuple *tuple,
		fate_cb cb, void *cb_arg,
		struct session_entry **result)
{
	struct session_table *table;
	struct session_entry *session;

	table = get_table(db, tuple->l4_proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		session = st6_find(table->t6, tuple);
		break;
	case L3PROTO_IPV4:
		session = st4_find(table->t4, tuple);
		break;
	default:
		WARN(true, "Unsupported network protocol: %u", tuple->l3_proto);
		spin_unlock_bh(&table->lock);
		return -EINVAL;
	}

	if (session) {
		session_get(session);
		if (cb)
			decide_fate(cb, cb_arg, table, session, NULL);
	}

	spin_unlock_bh(&table->lock);

	if (!session)
		return -ESRCH;

	*result = session;
	return 0;
}

static void attach_timer(struct session_entry *session,
		struct expire_timer *expirer)
{
	/*
	 * Please do not override session->update_time here;
	 * joold needs to define update time on its own.
	 */
	list_add_tail(&session->list_hook, &expirer->sessions);
	session->expirer = expirer;
}

/**
 * Note: This particular incarnation of fate_cb is not prepared to return
 * FATE_PROBE.
 */
int sessiondb_add(struct sessiondb *db, struct session_entry *session,
		fate_cb cb, void *cb_arg, bool est)
{
	struct session_table *table;
	struct session_entry *collision;

	table = get_table(db, session->l4_proto);
	if (!table)
		return -EINVAL;

	pktqueue_rm(db->pkt_queue, session);

	spin_lock_bh(&table->lock);

	/* Removing from t6 is faster than on t4, so let's add on t6 first */
	collision = st6_add(table->t6, session);
	if (collision)
		goto exists;

	collision = st4_add(table->t4, session);
	if (collision) {
		st6_rm(table->t6, session);
		goto exists;
	}

	attach_timer(session, est ? &table->est_timer : &table->trans_timer);
	session_get(session); /* Database's references. */
	table->count++;

	if (table->log_changes)
		session_log(session, "Added session");

	spin_unlock_bh(&table->lock);
	return 0;

exists:
	if (cb)
		decide_fate(cb, cb_arg, table, collision, NULL);
	spin_unlock_bh(&table->lock);
	return -EEXIST;
}

int sessiondb_add_simple(struct sessiondb *db, struct session_entry *session,
		bool est)
{
	return sessiondb_add(db, session, NULL, NULL, est);
}

int sessiondb_foreach(struct sessiondb *db, l4_protocol proto,
		struct session_foreach_func *func,
		struct session_foreach_offset *offset)
{
	struct session_table *table;
	int error;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	error = st6_foreach(table->t6, func, offset);
	spin_unlock_bh(&table->lock);

	return error;
}

int sessiondb_count(struct sessiondb *db, l4_protocol proto, __u64 *result)
{
	struct session_table *table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	*result = table->count;
	spin_unlock_bh(&table->lock);
	return 0;
}

static void destroy_session(struct session_entry *session, void *arg)
{
	struct session_table *table = arg;

	log_debug("Deleting session %pI4#%u -> %pI4#%u",
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4);

	st6_rm(table->t6, session);
	st4_rm(table->t4, session);
	list_del(&session->list_hook);
	/* TODO subtrees? */

	session_put(session, false);
}

static int destroy_session_return(struct session_entry *session, void *arg)
{
	destroy_session(session, arg);
	return 0;
}

void sessiondb_delete_by_bib(struct sessiondb *db, struct bib_entry *bib)
{
	struct session_table *table;
	struct destructor_arg destructor;

	table = get_table(db, bib->l4_proto);
	if (!table)
		return;

	destructor.cb = destroy_session;
	destructor.arg = table;

	spin_lock_bh(&table->lock);
	st4_prune_src4(table->t4, &bib->ipv4, &destructor);
	spin_unlock_bh(&table->lock);
}

void sessiondb_rm_range(struct sessiondb *db, l4_protocol proto,
		struct ipv4_range *range)
{
	struct session_table *table;
	struct destructor_arg destructor;

	table = get_table(db, proto);
	if (!table)
		return;

	destructor.cb = destroy_session;
	destructor.arg = table;

	spin_lock_bh(&table->lock);
	st4_prune_range(table->t4, range, &destructor);
	spin_unlock_bh(&table->lock);
}

void sessiondb_rm_prefix6(struct sessiondb *db, l4_protocol proto,
		struct ipv6_prefix *prefix)
{
	struct session_table *table;
	struct destructor_arg destructor;

	table = get_table(db, proto);
	if (!table)
		return;

	destructor.cb = destroy_session;
	destructor.arg = table;

	spin_lock_bh(&table->lock);
	st6_prune_range(table->t6, prefix, &destructor);
	spin_unlock_bh(&table->lock);
}

static void __clean(struct expire_timer *expirer,
		struct session_table *table,
		struct list_head *probes)
{
	struct session_entry *session;
	struct session_entry *tmp;

	list_for_each_entry_safe(session, tmp, &expirer->sessions, list_hook) {
		/*
		 * "list" is sorted by expiration date,
		 * so stop on the first unexpired session.
		 */
		if (time_before(jiffies, session->update_time + expirer->timeout))
			break;
		decide_fate(expirer->decide_fate_cb, NULL, table, session, probes);
	}
}

static void clean_table(struct session_table *table, struct net *ns)
{
	LIST_HEAD(probes);

	spin_lock_bh(&table->lock);
	__clean(&table->est_timer, table, &probes);
	__clean(&table->trans_timer, table, &probes);
	spin_unlock_bh(&table->lock);

	post_fate(ns, &probes);
}

/**
 * Forgets or downgrades (from EST to TRANS) old sessions.
 */
void sessiondb_clean(struct sessiondb *db, struct net *ns)
{
	clean_table(&db->udp, ns);
	clean_table(&db->tcp, ns);
	clean_table(&db->icmp, ns);
	pktqueue_clean(db->pkt_queue);
}

static void __flush(struct session_table *table)
{
	struct session_foreach_func func = {
			.cb = destroy_session_return,
			.arg = table,
	};

	spin_lock_bh(&table->lock);
	st6_foreach(table->t6, &func, NULL);
	spin_unlock_bh(&table->lock);
}

void sessiondb_flush(struct sessiondb *db)
{
	log_debug("Emptying the session tables...");

	__flush(&db->udp);
	__flush(&db->tcp);
	__flush(&db->icmp);
}
