#include "nat64/mod/stateful/session/db.h"

#include "nat64/common/constants.h"
#include "nat64/common/types.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateful/bib/bib.h"
#include "nat64/mod/stateful/session/pkt_queue.h"
#include "nat64/mod/stateful/session/table4.h"
#include "nat64/mod/stateful/session/table6.h"
#include "nat64/mod/stateful/session/table64.h"

struct expire_timer {
	struct list_head sessions;
	unsigned long timeout;
	bool is_established;
	fate_cb decide_fate_cb;
};

struct session_table {
	/**
	 * Indexes entries by [src4, dst4.l3, dst4.l4] triplet,
	 * prevents [src4, dst4.l3, dst4.l4] duplicates.
	 */
	struct session_table4 t4;
	/**
	 * Indexes entries by [src6, dst6] tuple,
	 * prevents [src6, dst6] duplicates.
	 */
	struct session_table6 t6;
	/**
	 * Indexes entries by [src6, src4] tuple,
	 * prevents [src6, src4] duplicates.
	 */
	struct session_table64 t64;

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

	/**
	 * Static BIB entries.
	 * (Dynamic BIB entries are inferred from the session tables.)
	 */
	struct bib *bib;

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

static void sessiontable_init(struct session_table *table, fate_cb expired_cb,
		int est_timeout, int trans_timeout)
{
	table->t4 = RB_ROOT;
	table->t6 = RB_ROOT;
	table->t64 = RB_ROOT;

	init_expirer(&table->est_timer, est_timeout, true, expired_cb);
	init_expirer(&table->trans_timer, trans_timeout, false, expired_cb);

	table->count = 0;
	table->log_changes = DEFAULT_SESSION_LOGGING;
	spin_lock_init(&table->lock);
}

int sessiondb_init(struct sessiondb **result)
{
	struct sessiondb *sdb;

	sdb = wkmalloc(struct sessiondb, GFP_KERNEL);
	if (!sdb)
		return -ENOMEM;

	sessiontable_init(&sdb->udp, just_die, UDP_DEFAULT, 0);
	sessiontable_init(&sdb->tcp, tcp_expired_cb, TCP_EST, TCP_TRANS);
	sessiontable_init(&sdb->icmp, just_die, ICMP_DEFAULT, 0);

	sdb->pkt_queue = pktqueue_create();
	if (!sdb->pkt_queue) {
		wkfree(struct sessiondb, sdb);
		return -ENOMEM;
	}

	sdb->bib = bibdb_init();
	if (!sdb->bib) {
		pktqueue_destroy(sdb->pkt_queue);
		wkfree(struct sessiondb, sdb);
		return -ENOMEM;
	}

	kref_init(&sdb->refs);

	*result = sdb;
	return 0;
}

void sessiondb_get(struct sessiondb *db)
{
	kref_get(&db->refs);
}

static void destroy_sessions(struct list_head *list, const bool log)
{
	struct session_entry *session;
	struct session_entry *tmp;

	list_for_each_entry_safe(session, tmp, list, list_hook) {
		session_put(session, false);
		if (log)
			session_log(session, "Forgot session");
	}
}

static void release(struct kref *refcounter)
{
	struct sessiondb *db;
	db = container_of(refcounter, struct sessiondb, refs);

	log_debug("Emptying the session tables...");
	destroy_sessions(&db->udp.est_timer.sessions, db->udp.log_changes);
	destroy_sessions(&db->udp.trans_timer.sessions, db->udp.log_changes);
	destroy_sessions(&db->tcp.est_timer.sessions, db->tcp.log_changes);
	destroy_sessions(&db->tcp.trans_timer.sessions, db->tcp.log_changes);
	destroy_sessions(&db->icmp.est_timer.sessions, db->icmp.log_changes);
	destroy_sessions(&db->icmp.trans_timer.sessions, db->icmp.log_changes);
	pktqueue_destroy(db->pkt_queue);
	bibdb_put(db->bib);

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
	struct session_table *table;
	int error;

	table = get_table(db, tuple4->l4_proto);
	if (!table)
		return -EINVAL;
	spin_lock_bh(&table->lock);

	error = st4_find_full(&table->t4, tuple4, bib, session, allow);
	if (error == -ESRCH) {
		/*
		 * Maybe the operator set up a static BIB entry for such an
		 * occasion.
		 */
		*allow = false;
		*session = NULL;
		error = bibdb_find(db->bib, tuple4, bib);
	}

	spin_unlock_bh(&table->lock);
	return error;
}

/**
 * @bib is optional.
 * (This can be useful if you only need to know if it is tabled.)
 */
int sessiondb_find_bib_by_tuple(struct sessiondb *db, struct tuple *tuple,
		struct bib_entry *bib)
{
	return sessiondb_find_bib4(db, &tuple->dst.addr4, tuple->l4_proto, bib);
}

int sessiondb_find_bib4(struct sessiondb *db,
		struct ipv4_transport_addr *addr,
		l4_protocol proto,
		struct bib_entry *bib)
{
	struct session_table *table;
	int error;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;
	spin_lock_bh(&table->lock);

	error = st4_find_bib(&table->t4, addr, bib);
	if (error == -ESRCH)
		error = bibdb_find4(db->bib, addr, proto, bib);

	spin_unlock_bh(&table->lock);
	return error;
}

/**
 * Removes all of this database's references towards "session", and drops its
 * refcount accordingly.
 *
 * "table"'s spinlock must already be held.
 */
static void rm(struct session_table *table, struct session_entry *session)
{
	st4_rm(&table->t4, session);
	st6_rm(&table->t6, session);
	st64_rm(&table->t64, session);
	list_del(&session->list_hook);
	session_put(session, false);
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
		session = st6_find(&table->t6, tuple);
		break;
	case L3PROTO_IPV4:
		session = st4_find(&table->t4, tuple);
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

	/*
	 * Removing from t4 is slowest.
	 * That's the only metric deciding this add order right now.
	 */
	/* TODO check static BIB collision */
	collision = st64_add(&table->t64, session);
	if (collision)
		goto exists64;
	collision = st6_add(&table->t6, session);
	if (collision)
		goto exists6;
	collision = st4_add(&table->t4, session);
	if (collision)
		goto exists4;

	attach_timer(session, est ? &table->est_timer : &table->trans_timer);
	session_get(session); /* Database's references. */
	table->count++;

	if (table->log_changes)
		session_log(session, "Added session");

	spin_unlock_bh(&table->lock);
	return 0;

exists4:
	st6_rm(&table->t6, session);
exists6:
	st64_rm(&table->t64, session);
exists64:
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
	error = st6_foreach(&table->t6, func, offset);
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

int sessiondb_queue(struct sessiondb *db, struct session_entry *session,
		struct packet *pkt)
{
	return pktqueue_add(db->pkt_queue, session, pkt);
}

static void destroy_session(struct session_entry *session, void *arg)
{
	struct session_table *table = arg;
	log_debug("Removing session %pI4#%u -> %pI4#%u",
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4);
	rm(table, session);
}

static int destroy_session_return(struct session_entry *session, void *arg)
{
	destroy_session(session, arg);
	return 0;
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
	st4_prune_range(&table->t4, range, &destructor);
	bibdb_rm_range(db->bib, range);
	spin_unlock_bh(&table->lock);
}

static void __rm_prefix6(struct session_table *table,
		struct ipv6_prefix *prefix)
{
	struct destructor_arg destructor;

	destructor.cb = destroy_session;
	destructor.arg = table;

	spin_lock_bh(&table->lock);
	st6_prune_range(&table->t6, prefix, &destructor);
	spin_unlock_bh(&table->lock);
}

void sessiondb_rm_prefix6(struct sessiondb *db, struct ipv6_prefix *prefix)
{
	__rm_prefix6(&db->tcp, prefix);
	__rm_prefix6(&db->udp, prefix);
	__rm_prefix6(&db->icmp, prefix);
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
	st6_foreach(&table->t6, &func, NULL);
	spin_unlock_bh(&table->lock);
}

void sessiondb_flush(struct sessiondb *db)
{
	log_debug("Emptying the session tables...");

	__flush(&db->udp);
	__flush(&db->tcp);
	__flush(&db->icmp);
}

int sessiondb_foreach_bib(struct sessiondb *db, l4_protocol proto,
			struct bib_foreach_func *func,
			struct ipv4_transport_addr *offset);

int sessiondb_count_bib(struct sessiondb *db, l4_protocol proto, __u64 *result)
{
	/*
	 * Why?
	 * If there are static BIB entries mapped to sessions,
	 * it's kind of hard to not count them twice.
	 */
	log_info("Sorry; not implemented anymore.");
	return -EINVAL;
}

int sessiondb_add_bib(struct sessiondb *db, struct bib_entry *new,
		struct bib_entry *old)
{
	return bibdb_add(db->bib, new, old);
}

int sessiondb_rm_bib(struct sessiondb *db, struct bib_entry *bib)
{
	struct session_table *table;
	struct destructor_arg destructor;
	int error;

	table = get_table(db, bib->l4_proto);
	if (!table)
		return -EINVAL;

	destructor.cb = destroy_session;
	destructor.arg = table;

	spin_lock_bh(&table->lock);
	/* TODO hmmmmmmmmmmmmmmmmmmm. ==/!= -ESRCH? */
	error = bibdb_rm(db->bib, bib);
	if (!error)
		st4_prune_src4(&table->t4, &bib->ipv4, &destructor);
	spin_unlock_bh(&table->lock);

	return error;
}

bool session_is_established(struct session_entry *session)
{
	return session->expirer->is_established;
}

unsigned long int session_get_timeout(struct session_entry *session)
{
	return session->expirer->timeout;
}
