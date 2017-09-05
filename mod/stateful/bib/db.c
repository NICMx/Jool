#include "nat64/mod/stateful/bib/db.h"

#include <net/ip6_checksum.h>

#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/wkmalloc.h"

/*
 * TODO (performance) Maybe pack this?
 */
struct tabled_session {
	struct ipv6_transport_addr src6;
	struct ipv4_transport_addr src4;
	struct ipv4_transport_addr dst4;
	l4_protocol proto;

	tcp_state state;

	struct rb_node hook6;
	struct rb_node hook4;

	unsigned long update_time;
	/** MUST NOT be NULL. */
	struct expire_timer *expirer;
	struct list_head list_hook;
};

/**
 * A session that is about to cause Jool to create and send a new packet.
 *
 * This can happen in two situations:
 * - An established TCP session has been hanging for too long and Jool wants to
 *   query the endpoints for status.
 *   This is done by sending an empty TCP packet that should simply be ACK'd.
 * - What initially seemed like a potential TCP SO ended up expiring after a 6-
 *   second wait so it has to be ICMP errored. See pkt_queue.h.
 */
struct probing_session {
	struct session_entry session;
	struct list_head list_hook;
};

struct expire_timer {
	struct list_head sessions;
	unsigned long timeout;
	session_timer_type type;
	fate_cb decide_fate_cb;
};

struct session_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;

	/* Write sessions on the log as they are created and destroyed? */
	bool log_sessions;

	/* Number of entries in this table. */
	u64 session_count;

	spinlock_t lock;

	/** Expires this table's established sessions. */
	struct expire_timer est_timer;

	/*
	 * =============================================================
	 * Fields below are only relevant in the TCP table.
	 * (If you need to know what "type 1" and "type 2" mean, see the
	 * pkt_queue module's .h.)
	 * =============================================================
	 */

	/**
	 * Expires this table's transitory sessions.
	 * This is initialized in the UDP/ICMP tables, but all their operations
	 * become no-ops.
	 */
	struct expire_timer trans_timer;
	/**
	 * Expires this table's type-2 packets and their sessions.
	 * This is initialized in the UDP/ICMP tables, but all their operations
	 * become no-ops.
	 */
	struct expire_timer syn4_timer;

	/** Current number of packets (of both types) in the table. */
	int pkt_count;
	/** Maximum storable packets (of both types) in the table. */
	unsigned int pkt_limit;
	/** Drop externally initiated TCP connections? */
	bool drop_v4_syn;
};

struct bib {
	/** The session table for UDP conversations. */
	struct session_table udp;
	/** The session table for TCP connections. */
	struct session_table tcp;
	/** The session table for ICMP conversations. */
	struct session_table icmp;

	struct kref refs;
};

static struct kmem_cache *session_cache;

#define alloc_bib(flags) wkmem_cache_alloc("bib entry", bib_cache, flags)
#define alloc_session(flags) wkmem_cache_alloc("session", session_cache, flags)
#define free_bib(bib) wkmem_cache_free("bib entry", bib_cache, bib)
#define free_session(session) wkmem_cache_free("session", session_cache, session)

static struct tabled_session *session6_entry(const struct rb_node *node)
{
	return node ? rb_entry(node, struct tabled_session, hook6) : NULL;
}

static struct tabled_session *session4_entry(const struct rb_node *node)
{
	return node ? rb_entry(node, struct tabled_session, hook4) : NULL;
}

/**
 * "[Convert] tabled BIB to BIB entry"
 */
static void tbtobe(struct tabled_session *tabled, struct bib_entry *bib)
{
	if (!bib)
		return;

	bib->ipv6 = tabled->src6;
	bib->ipv4 = tabled->src4;
	bib->l4_proto = tabled->proto;
}

/**
 * "[Convert] tabled session to session entry"
 */
static void tstose(struct tabled_session *tsession,
		struct session_entry *session)
{
	session->src6 = tsession->src6;
//	session->dst6 = *dst6; // TODO
	session->src4 = tsession->src4;
	session->dst4 = tsession->dst4;
	session->proto = tsession->proto;
	session->state = tsession->state;
	session->timer_type = tsession->expirer->type;
	session->update_time = tsession->update_time;
	session->timeout = tsession->expirer->timeout;
	session->has_stored = false;
}

/**
 * [Convert] tabled session to bib_session"
 */
static void tstobs(struct tabled_session *session, struct bib_session *bs)
{
	if (!bs)
		return;

	bs->bib_set = true;
	bs->session_set = true;
	tstose(session, &bs->session);
}

/**
 * One-liner to get the session table corresponding to the @proto protocol.
 */
static struct session_table *get_table(struct bib *db, l4_protocol proto)
{
	switch (proto) {
	case L4PROTO_TCP:
		return &db->tcp;
	case L4PROTO_UDP:
		return &db->udp;
	case L4PROTO_ICMP:
		return &db->icmp;
	case L4PROTO_OTHER:
		break;
	}

	WARN(true, "Unsupported transport protocol: %u.", proto);
	return NULL;
}

int bib_init(void)
{
	session_cache = kmem_cache_create("session_nodes",
			sizeof(struct tabled_session),
			0, 0, NULL);
	if (!session_cache) {
		return -ENOMEM;
	}

	return 0;
}

void bib_destroy(void)
{
	kmem_cache_destroy(session_cache);
}

static enum session_fate just_die(struct session_entry *session, void *arg)
{
	return FATE_RM;
}

static void init_expirer(struct expire_timer *expirer,
		unsigned long timeout,
		session_timer_type type,
		fate_cb fate_cb)
{
	INIT_LIST_HEAD(&expirer->sessions);
	expirer->timeout = msecs_to_jiffies(1000 * timeout);
	expirer->type = type;
	expirer->decide_fate_cb = fate_cb;
}

static void init_table(struct session_table *table,
		unsigned long est_timeout,
		unsigned long trans_timeout,
		fate_cb est_cb)
{
	table->tree6 = RB_ROOT;
	table->tree4 = RB_ROOT;
	table->log_sessions = DEFAULT_SESSION_LOGGING;
	table->session_count = 0;
	spin_lock_init(&table->lock);
	init_expirer(&table->est_timer, est_timeout, SESSION_TIMER_EST, est_cb);

	init_expirer(&table->trans_timer, trans_timeout, SESSION_TIMER_TRANS,
			just_die);
	/* TODO "just_die"? what about the stored packet? */
	init_expirer(&table->syn4_timer, TCP_INCOMING_SYN, SESSION_TIMER_SYN4,
			just_die);
	table->pkt_count = 0;
	table->pkt_limit = 0;
	table->drop_v4_syn = DEFAULT_DROP_EXTERNAL_CONNECTIONS;
}

struct bib *bib_create(void)
{
	struct bib *db;

	db = wkmalloc(struct bib, GFP_KERNEL);
	if (!db)
		return NULL;

	init_table(&db->udp, UDP_DEFAULT, 0, just_die);
	init_table(&db->tcp, TCP_EST, TCP_TRANS, tcp_est_expire_cb);
	init_table(&db->icmp, ICMP_DEFAULT, 0, just_die);

	db->tcp.pkt_limit = DEFAULT_MAX_STORED_PKTS;

	kref_init(&db->refs);

	return db;
}

void bib_get(struct bib *db)
{
	kref_get(&db->refs);
}

/**
 * Potentially includes laggy packet fetches; please do not hold spinlocks while
 * calling this function!
 */
static void release_session_entry(struct rb_node *node, void *arg)
{
	free_session(session4_entry(node));
}

static void release_bib(struct kref *refs)
{
	struct bib *db;
	db = container_of(refs, struct bib, refs);

	/*
	 * The trees share the entries, so only one tree of each protocol
	 * needs to be emptied.
	 */
	rbtree_clear(&db->udp.tree4, release_session_entry, NULL);
	rbtree_clear(&db->tcp.tree4, release_session_entry, NULL);
	rbtree_clear(&db->icmp.tree4, release_session_entry, NULL);

	wkfree(struct bib, db);
}

void bib_put(struct bib *db)
{
	kref_put(&db->refs, release_bib);
}

void bib_config_copy(struct bib *db, struct bib_config *config)
{
	spin_lock_bh(&db->tcp.lock);
	config->bib_logging = false;
	config->session_logging = db->tcp.log_sessions;
	config->drop_by_addr = false;
	config->ttl.tcp_est = db->tcp.est_timer.timeout;
	config->ttl.tcp_trans = db->tcp.trans_timer.timeout;
	config->max_stored_pkts = db->tcp.pkt_limit;
	config->drop_external_tcp = db->tcp.drop_v4_syn;
	spin_unlock_bh(&db->tcp.lock);

	spin_lock_bh(&db->udp.lock);
	config->ttl.udp = db->udp.est_timer.timeout;
	spin_unlock_bh(&db->udp.lock);

	spin_lock_bh(&db->icmp.lock);
	config->ttl.icmp = db->icmp.est_timer.timeout;
	spin_unlock_bh(&db->icmp.lock);
}

void bib_config_set(struct bib *db, struct bib_config *config)
{
	spin_lock_bh(&db->tcp.lock);
	db->tcp.log_sessions = config->session_logging;
	db->tcp.est_timer.timeout = config->ttl.tcp_est;
	db->tcp.trans_timer.timeout = config->ttl.tcp_trans;
	db->tcp.pkt_limit = config->max_stored_pkts;
	db->tcp.drop_v4_syn = config->drop_external_tcp;
	spin_unlock_bh(&db->tcp.lock);

	spin_lock_bh(&db->udp.lock);
	db->udp.log_sessions = config->session_logging;
	db->udp.est_timer.timeout = config->ttl.udp;
	spin_unlock_bh(&db->udp.lock);

	spin_lock_bh(&db->icmp.lock);
	db->icmp.log_sessions = config->session_logging;
	db->icmp.est_timer.timeout = config->ttl.icmp;
	spin_unlock_bh(&db->icmp.lock);
}

static void log_session(struct session_table *table,
		struct tabled_session *session,
		char *action)
{
	struct timeval tval;
	struct tm t;

	if (!table->log_sessions)
		return;

	do_gettimeofday(&tval);
	time_to_tm(tval.tv_sec, 0, &t);
	log_info("%ld/%d/%d %d:%d:%d (GMT) - %s %pI6c#%u|%pI4#%u|%pI4#%u|%s",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec, action,
			&session->src6.l3, session->src6.l4,
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4,
			l4proto_to_string(session->proto));
}

static void log_new_session(struct session_table *table,
		struct tabled_session *session)
{
	return log_session(table, session, "Added session");
}

/**
 * This function does not return a result because whatever needs to happen later
 * needs to happen regardless of probe status.
 *
 * This function does not actually send the probe; it merely prepares it so the
 * caller can commit to sending it after releasing the spinlock.
 */
static void handle_probe(struct session_table *table,
		struct list_head *probes,
		struct tabled_session *session,
		struct session_entry *tmp)
{
	struct probing_session *probe;

	if (WARN(!probes, "Probe needed but caller doesn't support it"))
		return;

	/*
	 * Why add a dummy session instead of the real one?
	 * In the case of TCP probes it's because the real session's list hook
	 * must remain attached to the database.
	 * In the case of ICMP errors it's because the fact that a session
	 * removal can cascade into a BIB entry removal really complicates
	 * things.
	 * This way requires this malloc but it's otherwise very clean.
	 */
	probe = wkmalloc(struct probing_session, GFP_ATOMIC);
	if (!probe)
		return;

	probe->session = *tmp;
	list_add(&probe->list_hook, probes);
}

static void rm(struct session_table *table,
		struct list_head *probes,
		struct tabled_session *session,
		struct session_entry *tmp)
{
	rb_erase(&session->hook6, &table->tree6);
	rb_erase(&session->hook4, &table->tree4);
	list_del(&session->list_hook);
	log_session(table, session, "Forgot session");
	free_session(session);
	table->session_count--;
}

static void handle_fate_timer(struct tabled_session *session,
		struct expire_timer *timer)
{
	session->update_time = jiffies;
	session->expirer = timer;
	list_del(&session->list_hook);
	list_add_tail(&session->list_hook, &timer->sessions);
}

static int queue_unsorted_session(struct session_table *table,
		struct tabled_session *session,
		session_timer_type timer_type,
		bool remove_first)
{
	struct expire_timer *expirer;
	struct list_head *list;
	struct list_head *cursor;
	struct tabled_session *old;

	switch (timer_type) {
	case SESSION_TIMER_EST:
		expirer = &table->est_timer;
		break;
	case SESSION_TIMER_TRANS:
		expirer = &table->trans_timer;
		break;
	case SESSION_TIMER_SYN4:
		expirer = &table->syn4_timer;
		break;
	default:
		log_warn_once("incoming joold session's timer (%d) is unknown.",
				timer_type);
		return -EINVAL;
	}

	list = &expirer->sessions;
	for (cursor = list->prev; cursor != list; cursor = cursor->prev) {
		old = list_entry(cursor, struct tabled_session, list_hook);
		if (old->update_time < session->update_time)
			break;
	}

	if (remove_first)
		list_del(&session->list_hook);
	list_add(&session->list_hook, cursor);
	session->expirer = expirer;
	return 0;
}

/**
 * Assumes result->session has been set (result->session_set is true).
 */
static verdict decide_fate(struct collision_cb *cb,
		struct session_table *table,
		struct tabled_session *session,
		struct list_head *probes)
{
	struct session_entry tmp;
	enum session_fate fate;

	if (!cb)
		return VERDICT_CONTINUE;

	tstose(session, &tmp);
	fate = cb->cb(&tmp, cb->arg);

	/* The callback above is entitled to tweak these fields. */
	session->state = tmp.state;
	session->update_time = tmp.update_time;
	/* Also the expirer, which is down below. */

	switch (fate) {
	case FATE_TIMER_EST:
		handle_fate_timer(session, &table->est_timer);
		break;

	case FATE_PROBE:
		/* TODO ICMP errors aren't supposed to drop down to TRANS. */
		handle_probe(table, probes, session, &tmp);
		/* Fall through. */
	case FATE_TIMER_TRANS:
		handle_fate_timer(session, &table->trans_timer);
		break;

	case FATE_RM:
		rm(table, probes, session, &tmp);
		break;

	case FATE_PRESERVE:
		break;
	case FATE_DROP:
		return VERDICT_DROP;

	case FATE_TIMER_SLOW:
		/*
		 * Nothing to do with the return value.
		 * If timer type was invalid, well don't change the expirer.
		 * We left a warning in the log.
		 */
		queue_unsorted_session(table, session, tmp.timer_type, true);
		break;
	}

	return VERDICT_CONTINUE;
}

/**
 * send_probe_packet - Sends a probe packet to @session's IPv6 endpoint,
 * to trigger a confirmation ACK if the connection is still alive.
 *
 * From RFC 6146 page 30.
 *
 * @session: the established session that has been inactive for too long.
 *
 * Best if not called with spinlocks held.
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

	/* TODO (performance) can't we just defer this to somebody else? */
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
		log_debug("dst_output() returned errcode %d.", error);
		goto fail;
	}

	return;

fail:
	log_debug("A TCP connection will probably break.");
}

/**
 * Sends all the probes and ICMP errors listed in @probes.
 */
static void post_fate(struct net *ns, struct list_head *probes)
{
	struct probing_session *probe;
	struct probing_session *tmp;

	list_for_each_entry_safe(probe, tmp, probes, list_hook) {
		send_probe_packet(ns, &probe->session);
		wkfree(struct probing_session, probe);
	}
}

struct slot_group {
	struct tree_slot tree6;
	struct tree_slot tree4;
};

static void commit_add(struct session_table *table, struct slot_group *slots)
{
	treeslot_commit(&slots->tree6);
	treeslot_commit(&slots->tree4);
	table->session_count++;
}

static void attach_timer(struct tabled_session *session,
		struct expire_timer *expirer)
{
	session->update_time = jiffies;
	session->expirer = expirer;
	list_add_tail(&session->list_hook, &expirer->sessions);
}

static int compare6_rbnode(const struct rb_node *a, const struct rb_node *b)
{
	return taddr6_compare(&session6_entry(a)->src6,
			&session6_entry(b)->src6);
}

static int compare4_rbnode(const struct rb_node *a, const struct rb_node *b)
{
	struct tabled_session *sa = session4_entry(a);
	struct tabled_session *sb = session4_entry(b);
	int delta;

	delta = taddr4_compare(&sa->src4, &sb->src4);
	if (delta)
		return delta;

	return taddr4_compare(&sa->dst4, &sb->dst4);
}

static int compare6(const struct tabled_session *session,
		const struct ipv6_transport_addr *addr)
{
	return taddr6_compare(&session->src6, addr);
}

static int compare4(const struct tabled_session *session,
		const struct tuple *tuple4)
{
	int delta;

	delta = taddr4_compare(&session->src4, &tuple4->dst.addr4);
	if (delta)
		return delta;

	return taddr4_compare(&session->dst4, &tuple4->src.addr4);
}

static struct tabled_session *find_slot6(struct session_table *table,
		struct tabled_session *new,
		struct tree_slot *slot)
{
	struct rb_node *collision;
	collision = rbtree_find_slot(&new->hook6, &table->tree6,
			compare6_rbnode, slot);
	return session6_entry(collision);
}

static struct tabled_session *find_slot4(struct session_table *table,
		struct tabled_session *new,
		struct tree_slot *slot)
{
	struct rb_node *collision;
	collision = rbtree_find_slot(&new->hook4, &table->tree4,
			compare4_rbnode, slot);
	return session4_entry(collision);
}

static struct tabled_session *find_session6(struct session_table *table,
		struct ipv6_transport_addr *addr)
{
	return rbtree_find(addr, &table->tree6, compare6, struct tabled_session,
			hook6);
}

static struct tabled_session *find_session4(struct session_table *table,
		struct tuple *tuple4)
{
	return rbtree_find(tuple4, &table->tree4, compare4,
			struct tabled_session, hook4);
}

static struct tabled_session *create_session6(struct tuple *tuple6,
		struct ipv4_transport_addr *dst4,
		tcp_state state)
{
	struct tabled_session *session;

	session = alloc_session(GFP_ATOMIC);
	if (!session)
		return NULL;

	session->src6 = tuple6->src.addr6;
	session->dst4 = *dst4;
	session->proto = tuple6->l4_proto;
	session->state = state;
	return session;
}

static struct tabled_session *create_session(struct session_entry *session)
{
	struct tabled_session *result;

	session = alloc_session(GFP_ATOMIC);
	if (!session)
		return NULL;

	/*
	 * Hooks, most expirer fields and session->bib are left uninitialized
	 * since they depend on database knowledge.
	 */
	result->src6 = session->src6;
	result->src4 = session->src4;
	result->dst4 = session->dst4;
	result->proto = session->proto;
	result->state = session->state;
	result->update_time = session->update_time;
	return result;
}

/**
 * Boilerplate code to finish hanging @session on one af @table's trees.
 * 6-to-4 direction.
 *
 * It assumes @slots already describes the tree containers where the entries are
 * supposed to be added.
 */
static void commit_add6(struct session_table *table,
		struct tabled_session *session,
		struct slot_group *slots,
		struct expire_timer *expirer,
		struct bib_session *result)
{
	commit_add(table, slots);
	attach_timer(session, expirer);
	log_new_session(table, session);
	tstobs(session, result);
}

/**
 * Boilerplate code to finish hanging *@new on one af @table's trees.
 * joold version.
 *
 * It assumes @slots already describes the tree containers where the entries are
 * supposed to be added.
 */
static int commit_add64(struct session_table *table,
		struct tabled_session *session,
		struct slot_group *slots,
		session_timer_type timer_type)
{
	int error;

	error = queue_unsorted_session(table, session, timer_type, false);
	if (error)
		return error;

	commit_add(table, slots);
	log_new_session(table, session);
	return 0;
}

struct detach_args {
	struct session_table *table;
	struct sk_buff *probes;
	unsigned int detached;
};

static void detach_session(struct session_table *table,
		struct tabled_session *session)
{
	rb_erase(&session->hook6, &table->tree6);
	rb_erase(&session->hook4, &table->tree4);
	list_del(&session->list_hook);
	free_session(session);
	table->session_count--;
}

/**
 * Tests whether @predecessor's immediate succesor tree slot is a suitable
 * placeholder for @session. Returns the colliding node.
 *
 * (That is, returns NULL on success, a collision on failure.)
 *
 * In other words:
 * Assumes that @predecessor belongs to @table's v4 tree and that it is
 * @session's predecessor. (ie. @predecessor's transport address is @session's
 * transport address - 1.) You want to test whether @session can be inserted to
 * the tree.
 * If @predecessor's succesor collides with @session (ie. it has @session's v4
 * address), it returns the colliding succesor.
 * If @predecessor's succesor does not collide with @session, it returns NULL
 * and initializes @slot so you can actually add @session to the tree.
 */
static struct tabled_session *try_next(struct session_table *table,
		struct tabled_session *predecessor,
		struct tabled_session *session,
		struct tree_slot *slot)
{
	struct tabled_session *next;

	next = session4_entry(rb_next(&predecessor->hook4));
	if (!next) {
		/* There is no succesor and therefore no collision. */
		slot->tree = &table->tree4;
		slot->entry = &session->hook4;
		slot->parent = &predecessor->hook4;
		slot->rb_link = &slot->parent->rb_right;
		return NULL;
	}

	if (taddr4_equals(&next->src4, &session->src4))
		return next; /* Next is yet another collision. */

	slot->tree = &table->tree4;
	slot->entry = &session->hook4;
	if (predecessor->hook4.rb_right) {
		slot->parent = &next->hook4;
		slot->rb_link = &slot->parent->rb_left;
	} else {
		slot->parent = &predecessor->hook4;
		slot->rb_link = &slot->parent->rb_right;
	}
	return NULL;
}

/**
 * This is this function in pseudocode form:
 *
 * 	// wraps around until offset - 1
 * 	foreach (mask in @masks starting from some offset)
 * 		if (mask is not taken by an existing session entry from @table)
 * 			init the new session entry, @session, using mask
 * 			init @slot as the tree slot where @session should be added
 * 			return success (ie. 0)
 * 	return failure (-ENOENT)
 *
 */
static int find_available_mask(struct session_table *table,
		struct mask_domain *masks,
		struct tabled_session *session,
		struct tree_slot *slot)
{
	struct tabled_session *collision = NULL;
	int error;
	bool consecutive;

	/*
	 * We're going to assume the masks are generally consecutive.
	 * I think it's a fair assumption until someone requests otherwise as a
	 * new feature.
	 * This allows us to find an unoccupied mask with minimal further tree
	 * traversal.
	 */
	do {
		error = mask_domain_next(masks, &session->src4, &consecutive);
		if (error)
			return error;

		/*
		 * Just for the sake of clarity:
		 * @consecutive is never true on the first iteration.
		 */
		collision = consecutive
				? try_next(table, collision, session, slot)
				: find_slot4(table, session, slot);
	} while (collision);

	return 0;
}

static bool issue216_needed(struct mask_domain *masks,
		struct tabled_session *old)
{
	if (!masks)
		return false;
	return mask_domain_is_dynamic(masks)
			&& !mask_domain_matches(masks, &old->src4);
}

/**
 * This is a find and an add at the same time.
 *
 * If @new needs to be added, initializes @slots.
 * If @new collides, you will find the collision in @old.
 *
 * @masks will be used to init @new->local4 if applies.
 */
static int find_bib_session6(struct session_table *table,
		struct mask_domain *masks,
		struct tabled_session *new,
		struct tabled_session **old,
		struct slot_group *slots)
{
	int error;

	/*
	 * Please be careful around this function. All it wants to do is
	 * find/add, but it is constrained by several requirements at the same
	 * time:
	 *
	 * 1. If @new->bib->proto is ICMP (ie. 3-tuple), then
	 *    @new->session->dst4.l4 is invalid and needs to be patched. Though
	 *    it cannot be patched until we acquire a valid BIB entry.
	 *    (dst4.l4 is just fat that should not be used in 3-tuple
	 *    translation code, but a chunk of Jool assumes that
	 *    dst4.l4 == dst6.l4 in 5-tuples and dst4.l4 == src4.l4 in
	 *    3-tuples.)
	 * 2. @masks can be NULL!
	 *    If this happens, just assume that @old->bib->src4 and
	 *    (once acquired) @new->bib->src4 are both valid.
	 *
	 * See below for more stuff.
	 */

	*old = find_slot6(table, new, &slots->tree6);
	if (*old) {
		if (!issue216_needed(masks, *old)) {
			if (new->proto == L4PROTO_ICMP)
				new->dst4.l4 = (*old)->src4.l4;
			return 0; /* Typical happy path for existing sessions */
		}

		/*
		 * Issue #216:
		 * If pool4 was empty (when @masks was generated) and the BIB
		 * entry's IPv4 address is no longer a mask candidate, drop the
		 * BIB entry and recompute it from scratch.
		 * https://github.com/NICMx/Jool/issues/216
		 */
		log_debug("Issue #216.");
		detach_session(table, *old);

		/*
		 * The detaching above might have involved a rebalance.
		 * I believe that completely invalidates the bib6 slot.
		 * Tough luck; we'll need another lookup.
		 * At least this only happens on empty pool4s. (Low traffic.)
		 */
		*old = find_slot6(table, new, &slots->tree6);
		if (WARN(*old, "Found a session entry I just removed!"))
			return -EINVAL;
	}

	/*
	 * In case you're tweaking this function: By this point, *old has to be
	 * NULL and slots->tree6 has to be a valid potential tree slot. We're
	 * now in create-new-session mode.
	 * Time to worry about slots->tree4.
	 */
	if (masks) {
		error = find_available_mask(table, masks, new, &slots->tree4);
		if (error) {
			if (WARN(error != -ENOENT, "Unknown error: %d", error))
				return error;
			log_warn_once("I ran out of pool4 addresses.");
			return error;
		}

		if (new->proto == L4PROTO_ICMP)
			new->dst4.l4 = new->src4.l4;

	} else {
		/*
		 * TODO (issue113) perhaps the sender's session shold be trusted
		 * more.
		 */
		if (find_slot4(table, new, &slots->tree4))
			return -EEXIST;
	}

	return 0; /* Happy path for new sessions */
}

/**
 * @db current BIB & session database.
 * @masks Should a BIB entry be created, its IPv4 address mask will be allocated
 *     from one of these candidates.
 * @tuple6 The connection that you want to mask.
 * @dst4 translated version of @tuple.dst.addr6.
 * @result A copy of the resulting BIB entry and session from the database will
 *     be placed here. (if not NULL)
 */
int bib_add6(struct bib *db,
		struct mask_domain *masks,
		struct tuple *tuple6,
		struct ipv4_transport_addr *dst4,
		struct bib_session *result)
{
	struct session_table *table;
	struct tabled_session *new;
	struct tabled_session *old;
	struct slot_group slots;
	int error;

	table = get_table(db, tuple6->l4_proto);
	if (!table)
		return -EINVAL;

	/*
	 * We might have a lot to do. This function may index two RB-trees
	 * so spinlock time is tight.
	 *
	 * Let's start by allocating and initializing the objects as much as we
	 * can, even if we end up not needing them.
	 */
	new = create_session6(tuple6, dst4, ESTABLISHED);
	if (!new)
		return -ENOMEM;

	spin_lock_bh(&table->lock); /* Here goes... */

	error = find_bib_session6(table, masks, new, &old, &slots);
	if (error)
		goto end;

	if (old) { /* Session already exists. */
		handle_fate_timer(old, &table->est_timer);
		tstobs(old, result);
		goto end;
	}

	/* New connection; add the session. */
	commit_add6(table, new, &slots, &table->est_timer, result);
	new = NULL; /* Do not free! */
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new)
		free_session(new);

	return error;
}

/**
 * See @bib_add6.
 */
int bib_add4(struct bib *db,
		struct ipv6_transport_addr *dst6,
		struct tuple *tuple4,
		struct bib_session *result)
{
	struct session_table *table;
	struct tabled_session *session;
	int error;

	table = get_table(db, tuple4->l4_proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);

	session = find_session4(table, tuple4);
	if (!session) {
		error = -ESRCH;
		goto end;
	}

	handle_fate_timer(session, &table->est_timer);
	tstobs(session, result);
	error = 0;
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);
	return error;
}

/**
 * Note: This particular incarnation of fate_cb is not prepared to return
 * FATE_PROBE.
 */
verdict bib_add_tcp6(struct bib *db,
		struct mask_domain *masks,
		struct ipv4_transport_addr *dst4,
		struct packet *pkt,
		struct collision_cb *cb,
		struct bib_session *result)
{
	struct session_table *table;
	struct tabled_session *new;
	struct tabled_session *old;
	struct slot_group slots;
	verdict verdict;

	if (WARN(pkt->tuple.l4_proto != L4PROTO_TCP, "Incorrect l4 proto in TCP handler."))
		return VERDICT_DROP;

	new = create_session6(&pkt->tuple, dst4, V6_INIT);
	if (!new)
		return VERDICT_DROP;

	table = &db->tcp;
	spin_lock_bh(&table->lock);

	if (find_bib_session6(table, masks, new, &old, &slots)) {
		verdict = VERDICT_DROP;
		goto end;
	}

	if (old) {
		/* All states except CLOSED. */
		verdict = decide_fate(cb, table, old, NULL);
		if (verdict == VERDICT_CONTINUE)
			tstobs(old, result);
		goto end;
	}

	/* CLOSED state beginning now. */

	if (!pkt_tcp_hdr(pkt)->syn) {
		log_debug("Packet is not SYN and lacks state.");
		verdict = VERDICT_DROP;
		goto end;
	}

	commit_add6(table, new, &slots, &table->trans_timer, result);
	new = NULL; /* Do not free! */
	verdict = VERDICT_CONTINUE;
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new)
		free_session(new);

	return verdict;
}

/**
 * Note: This particular incarnation of fate_cb is not prepared to return
 * FATE_PROBE.
 */
verdict bib_add_tcp4(struct bib *db,
		struct ipv6_transport_addr *dst6,
		struct packet *pkt,
		struct collision_cb *cb,
		struct bib_session *result)
{
	struct session_table *table;
	struct tabled_session *session;
	verdict verdict;

	if (WARN(pkt->tuple.l4_proto != L4PROTO_TCP, "Incorrect l4 proto in TCP handler."))
		return VERDICT_DROP;

	table = &db->tcp;
	spin_lock_bh(&table->lock);

	session = find_session4(table, &pkt->tuple);

	if (!session) {
		/* CLOSED state beginning now. */
		log_debug("Connection being initialized from v4.");
		verdict = VERDICT_DROP;
		goto end;
	}

	/* All states except CLOSED. */
	verdict = decide_fate(cb, table, session, NULL);
	if (verdict == VERDICT_CONTINUE)
		tstobs(session, result);
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);
	return verdict;
}

/**
 * Initializes @result's BIB fields. Only the BIB fields!
 */
int bib_find(struct bib *db, struct tuple *tuple, struct bib_session *result)
{
	struct bib_entry tmp;
	int error;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		error = bib_find6(db, tuple->l4_proto, &tuple->src.addr6, &tmp);
		break;
	case L3PROTO_IPV4:
		error = bib_find4(db, tuple->l4_proto, tuple, &tmp);
		break;
	default:
		WARN(true, "Unknown layer 3 protocol: %u", tuple->l3_proto);
		return -EINVAL;
	}

	if (error)
		return error;

	result->bib_set = true;
	result->session.src6 = tmp.ipv6;
	result->session.src4 = tmp.ipv4;
	result->session.proto = tmp.l4_proto;
	return 0;
}

int bib_add_session(struct bib *db,
		struct session_entry *session,
		struct collision_cb *cb)
{
	struct session_table *table;
	struct tabled_session *new;
	struct tabled_session *old;
	struct slot_group slots;
	int error;

	table = get_table(db, session->proto);
	if (!table)
		return -EINVAL;

	new = create_session(session);
	if (!new)
		return -ENOMEM;

	spin_lock_bh(&table->lock);

	error = find_bib_session6(table, NULL, new, &old, &slots);
	if (error)
		goto end;

	if (old) {
		/* There's no packet; ignore the verdict. */
		decide_fate(cb, table, old, NULL);
		goto end;
	}

	error = commit_add64(table, new, &slots, session->timer_type);
	new = NULL; /* Do not free! */
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new)
		free_session(new);

	return error;
}

static void __clean(struct expire_timer *expirer,
		struct session_table *table,
		struct list_head *probes)
{
	struct tabled_session *session;
	struct tabled_session *tmp;
	struct collision_cb cb;

	cb.cb = expirer->decide_fate_cb;
	cb.arg = NULL;

	list_for_each_entry_safe(session, tmp, &expirer->sessions, list_hook) {
		/*
		 * "list" is sorted by expiration date,
		 * so stop on the first unexpired session.
		 */
		if (time_before(jiffies, session->update_time + expirer->timeout))
			break;
		decide_fate(&cb, table, session, probes);
	}
}

static void clean_table(struct session_table *table, struct net *ns)
{
	LIST_HEAD(probes);

	spin_lock_bh(&table->lock);
	__clean(&table->est_timer, table, &probes);
	__clean(&table->trans_timer, table, &probes);
	__clean(&table->syn4_timer, table, &probes);
	spin_unlock_bh(&table->lock);

	post_fate(ns, &probes);
}

/**
 * Forgets or downgrades (from EST to TRANS) old sessions.
 */
void bib_clean(struct bib *db, struct net *ns)
{
	clean_table(&db->udp, ns);
	clean_table(&db->tcp, ns);
	clean_table(&db->icmp, ns);
}

static struct rb_node *find_starting_point(struct session_table *table,
		const struct tuple *offset,
		bool include_offset)
{
	struct tabled_session *session;
	struct rb_node **node;
	struct rb_node *parent;

	/* If there's no offset, start from the beginning. */
	if (!offset)
		return rb_first(&table->tree4);

	/* If offset is found, start from offset or offset's next. */
	rbtree_find_node(offset, &table->tree4, compare4,
			struct tabled_session, hook4, parent, node);
	if (*node)
		return include_offset ? (*node) : rb_next(*node);

	if (!parent)
		return NULL;

	/*
	 * If offset is not found, start from offset's next anyway.
	 * (If offset was meant to exist, it probably timed out and died while
	 * the caller wasn't holding the spinlock; it's nothing to worry about.)
	 */
	session = rb_entry(parent, struct tabled_session, hook4);
	return (compare4(session, offset) < 0) ? rb_next(parent) : parent;
}

static struct rb_node *slot_next(struct tree_slot *slot)
{
	if (!slot->parent)
		return NULL;
	if (&slot->parent->rb_left == slot->rb_link)
		return slot->parent;
	/* else if (slot->parent->rb_right == &slot->rb_link) */
	return rb_next(slot->parent);
}

/**
 * Finds the BIB entry and/or session where a foreach of the sessions should
 * start with, based on @offset.
 *
 * If @offset is not found, it always tries to return the session that would
 * follow one that would match perfectly. This is because sessions expiring
 * during ongoing fragmented foreaches are not considered a problem.
 */
static struct tabled_session *find_session_offset(struct session_table *table,
		struct session_foreach_offset *offset)
{
	struct tabled_session tmp;
	struct tree_slot slot;
	struct tabled_session *result;

	tmp.src4 = offset->offset.src;
	tmp.dst4 = offset->offset.dst;
	result = find_slot4(table, &tmp, &slot);

	if (!result)
		return session4_entry(slot_next(&slot));

	if (!offset->include_offset)
		return session4_entry(rb_next(&result->hook4));

	return result;
}

#define foreach_session(table, node) \
		for (node = session4_entry(rb_first(&table->tree4)); \
				node; \
				node = session4_entry(rb_next(&node->hook4)))

int bib_foreach_session(struct bib *db, l4_protocol proto,
		struct session_foreach_func *func,
		struct session_foreach_offset *offset)
{
	struct session_table *table;
	struct tabled_session *pos;
	struct session_entry tmp;
	int error = 0;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);

	if (offset) {
		pos = find_session_offset(table, offset);
		if (pos)
			goto goto_session;
		goto end;
	}

	foreach_session(table, pos) {
goto_session:	tstose(pos, &tmp);
		error = func->cb(&tmp, func->arg);
		if (error)
			goto end;
	}


end:
	spin_unlock_bh(&table->lock);
	return error;
}

#undef foreach_session

int bib_find6(struct bib *db, l4_protocol proto,
		struct ipv6_transport_addr *addr,
		struct bib_entry *result)
{
	struct session_table *table;
	struct tabled_session *session;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	session = find_session6(table, addr);
	if (session)
		tbtobe(session, result);
	spin_unlock_bh(&table->lock);

	return session ? 0 : -ESRCH;
}

int bib_find4(struct bib *db, l4_protocol proto,
		struct tuple *tuple4,
		struct bib_entry *result)
{
	struct session_table *table;
	struct tabled_session *session;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	session = find_session4(table, tuple4);
	if (session)
		tbtobe(session, result);
	spin_unlock_bh(&table->lock);

	return session ? 0 : -ESRCH;
}

void bib_rm_range(struct bib *db, l4_protocol proto, struct ipv4_range *range)
{
	struct session_table *table;
	struct tuple offset;
	struct rb_node *node;
	struct rb_node *next;
	struct tabled_session *session;

	table = get_table(db, proto);
	if (!table)
		return;

	offset.dst.addr4.l3 = range->prefix.address;
	offset.dst.addr4.l4 = range->ports.min;
	memset(&offset.src, 0, sizeof(offset.src));

	spin_lock_bh(&table->lock);

	node = find_starting_point(table, &offset, true);
	for (; node; node = next) {
		next = rb_next(node);
		session = session4_entry(node);

		if (!prefix4_contains(&range->prefix, &session->src4.l3))
			break;
		if (port_range_contains(&range->ports, session->src4.l4))
			detach_session(table, session);
	}

	spin_unlock_bh(&table->lock);
}

static void flush_table(struct session_table *table)
{
	struct rb_node *node;
	struct rb_node *next;

	spin_lock_bh(&table->lock);

	for (node = rb_first(&table->tree4); node; node = next) {
		next = rb_next(node);
		detach_session(table, session4_entry(node));
	}

	spin_unlock_bh(&table->lock);
}

void bib_flush(struct bib *db)
{
	flush_table(&db->tcp);
	flush_table(&db->udp);
	flush_table(&db->icmp);
}

int bib_count_sessions(struct bib *db, l4_protocol proto, __u64 *count)
{
	struct session_table *table;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	*count = table->session_count;
	spin_unlock_bh(&table->lock);
	return 0;
}

static void print_tabs(int tabs)
{
	int i;
	for (i = 0; i < tabs; i++)
		pr_cont("  ");
}

static void print_session(struct rb_node *node, int tabs, char *prefix)
{
	struct tabled_session *session;

	if (!node)
		return;

	session = session4_entry(node);
	print_tabs(tabs);
	pr_cont("[%s] %pI6c#%u %pI4#%u %pI4#%u\n", prefix,
			&session->src6.l3, session->src6.l4,
			&session->src4.l3, session->src4.l4,
			&session->dst4.l3, session->dst4.l4);

	print_session(node->rb_left, tabs + 1, "L"); /* "Left" */
	print_session(node->rb_right, tabs + 1, "R"); /* "Right" */
}

void bib_print(struct bib *db)
{
	log_debug("TCP:");
	print_session(db->tcp.tree4.rb_node, 1, "Tree");
	log_debug("UDP:");
	print_session(db->udp.tree4.rb_node, 1, "Tree");
	log_debug("ICMP:");
	print_session(db->icmp.tree4.rb_node, 1, "Tree");
}
