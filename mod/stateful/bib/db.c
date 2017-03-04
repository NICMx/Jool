#include "nat64/mod/stateful/bib/db.h"

#include <net/ip6_checksum.h>

#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateful/bib/pkt_queue.h"

/*
 * TODO (performance) Maybe pack this?
 */
struct tabled_bib {
	struct ipv6_transport_addr src6;
	struct ipv4_transport_addr src4;
	l4_protocol proto;
	bool is_static;

	struct rb_node hook6;
	struct rb_node hook4;

	struct rb_root sessions;
};

/*
 * TODO (performance) Maybe pack this?
 */
struct tabled_session {
	/**
	 * We don't strictly need to store @dst6; @dst6 is always @dst4 plus the
	 * pool6 prefix. But we store it anyway so I don't have to make more
	 * mess constatly in this module.
	 */
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr dst4;
	tcp_state state;
	/** MUST NOT be NULL. */
	struct tabled_bib *bib;

	/**
	 * Sessions only need one tree. The rationale is different for TCP/UDP
	 * vs ICMP sessions:
	 *
	 * In TCP and UDP the dst4 address is just the dst6 address minus the
	 * pool6 prefix. Therefore, and assuming the pool6 prefix stays still
	 * (something I'm well willing to enforce), sessions indexed by dst4
	 * yield exactly the same tree as sessions indexed by dst6.
	 *
	 * In ICMP, dst4.l4 is the same as src4.l4 instead of dst6.l4. This
	 * would normally mean that dst6 sessions would yield a different tree
	 * than dst4 sessions. Luckily, this is not the case because dst4.l4 is
	 * not meaningful to the tree search in ICMP sessions; sessions are
	 * already grouped by BIB entry, which means all of a BIB entry's
	 * sessions will have different dst4.l3. (Which has more precedence than
	 * dst4.l4 during searches.)
	 * (And again, dst4.l3 is just dst6.l3 minus the prefix.)
	 *
	 * This might be a little annoying to wrap one's head around, but I
	 * think it's really nice that we only need to search and rebalance
	 * three trees (instead of four) whenever we need to add a BIB/session
	 * couple during translation.
	 * It's also a very elegant hack; it doesn't result in any special case
	 * handling in the whole code below.
	 */
	struct rb_node tree_hook;

	unsigned long update_time;
	/** MUST NOT be NULL. */
	struct expire_timer *expirer;
	struct list_head list_hook;

	/** See pke_queue.h for some thoughts on stored packets. */
	struct sk_buff *stored;
};

struct bib_session_tuple {
	struct tabled_bib *bib;
	struct tabled_session *session;
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
	struct sk_buff *skb;
	struct list_head list_hook;
};

struct expire_timer {
	struct list_head sessions;
	unsigned long timeout;
	session_timer_type type;
	fate_cb decide_fate_cb;
};

struct bib_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;

	/* Write BIB entries on the log as they are created and destroyed? */
	bool log_bibs;
	/* Write sessions on the log as they are created and destroyed? */
	bool log_sessions;
	/**
	 * Is Address-Dependent Filtering active?
	 * This is only relevant in TCP and UDP; ADF does not make sense on
	 * ICMP.
	 */
	bool drop_by_addr;

	/* Number of entries in this table. */
	u64 bib_count;
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

	/**
	 * Packet storage for type 1 packets.
	 * This is NULL in UDP/ICMP.
	 */
	struct pktqueue *pkt_queue;
};

struct bib {
	/** The session table for UDP conversations. */
	struct bib_table udp;
	/** The session table for TCP connections. */
	struct bib_table tcp;
	/** The session table for ICMP conversations. */
	struct bib_table icmp;

	struct kref refs;
};

static struct kmem_cache *bib_cache;
static struct kmem_cache *session_cache;

#define alloc_bib(flags) wkmem_cache_alloc("bib entry", bib_cache, flags)
#define alloc_session(flags) wkmem_cache_alloc("session", session_cache, flags)
#define free_bib(bib) wkmem_cache_free("bib entry", bib_cache, bib)
#define free_session(session) wkmem_cache_free("session", session_cache, session)

static struct tabled_bib *bib6_entry(const struct rb_node *node)
{
	return node ? rb_entry(node, struct tabled_bib, hook6) : NULL;
}

static struct tabled_bib *bib4_entry(const struct rb_node *node)
{
	return node ? rb_entry(node, struct tabled_bib, hook4) : NULL;
}

static struct tabled_session *node2session(const struct rb_node *node)
{
	return node ? rb_entry(node, struct tabled_session, tree_hook) : NULL;
}

/**
 * "[Convert] tabled BIB to BIB entry"
 */
static void tbtobe(struct tabled_bib *tabled, struct bib_entry *bib)
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
	session->src6 = tsession->bib->src6;
	session->dst6 = tsession->dst6;
	session->src4 = tsession->bib->src4;
	session->dst4 = tsession->dst4;
	session->proto = tsession->bib->proto;
	session->state = tsession->state;
	session->timer_type = tsession->expirer->type;
	session->update_time = tsession->update_time;
	session->timeout = tsession->expirer->timeout;
	session->has_stored = !!tsession->stored;
}

/**
 * "[Convert] tabled BIB to bib_session"
 */
static void tbtobs(struct tabled_bib *tabled, struct bib_session *bs)
{
	if (!bs)
		return;

	bs->bib_set = true;
	bs->session.src6 = tabled->src6;
	bs->session.src4 = tabled->src4;
	bs->session.proto = tabled->proto;
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
static struct bib_table *get_table(struct bib *db, l4_protocol proto)
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

static void kill_stored_pkt(struct bib_table *table,
		struct tabled_session *session)
{
	if (!session->stored)
		return;

	log_debug("Deleting stored type 2 packet.");
	kfree_skb(session->stored);
	session->stored = NULL;
	table->pkt_count--;
}

int bib_init(void)
{
	bib_cache = kmem_cache_create("bib_nodes",
			sizeof(struct tabled_bib),
			0, 0, NULL);
	if (!bib_cache)
		return -ENOMEM;

	session_cache = kmem_cache_create("session_nodes",
			sizeof(struct tabled_session),
			0, 0, NULL);
	if (!session_cache) {
		kmem_cache_destroy(bib_cache);
		return -ENOMEM;
	}

	return 0;
}

void bib_destroy(void)
{
	kmem_cache_destroy(bib_cache);
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

static void init_table(struct bib_table *table,
		unsigned long est_timeout,
		unsigned long trans_timeout,
		fate_cb est_cb)
{
	table->tree6 = RB_ROOT;
	table->tree4 = RB_ROOT;
	table->log_bibs = DEFAULT_BIB_LOGGING;
	table->log_sessions = DEFAULT_SESSION_LOGGING;
	table->drop_by_addr = DEFAULT_ADDR_DEPENDENT_FILTERING;
	table->bib_count = 0;
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
	table->pkt_queue = NULL;
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
	db->tcp.pkt_queue = pktqueue_create();
	if (!db->tcp.pkt_queue) {
		wkfree(struct bib, db);
		return NULL;
	}
	/*
	 * Just in case some crazy psycho decides to change the default.
	 * THERE IS NO ADRESS-DEPENDENT FILTERING ON ICMP; the RFC is wrong.
	 */
	db->icmp.drop_by_addr = false;

	kref_init(&db->refs);

	return db;
}

void bib_get(struct bib *db)
{
	kref_get(&db->refs);
}

/**
 * Potentially includes a laggy packet fetch; please do not hold spinlocks while
 * calling this function!
 */
static void release_session(struct rb_node *node, void *arg)
{
	struct tabled_session *session = node2session(node);

	if (session->stored) {
		icmp64_send_skb(session->stored, ICMPERR_PORT_UNREACHABLE, 0);
		kfree_skb(session->stored);
	}

	free_session(session);
}

/**
 * Potentially includes laggy packet fetches; please do not hold spinlocks while
 * calling this function!
 */
static void release_bib_entry(struct rb_node *node, void *arg)
{
	struct tabled_bib *bib = bib4_entry(node);
	rbtree_clear(&bib->sessions, release_session, NULL);
	free_bib(bib);
}

static void release_bib(struct kref *refs)
{
	struct bib *db;
	db = container_of(refs, struct bib, refs);

	/*
	 * The trees share the entries, so only one tree of each protocol
	 * needs to be emptied.
	 */
	rbtree_clear(&db->udp.tree4, release_bib_entry, NULL);
	rbtree_clear(&db->tcp.tree4, release_bib_entry, NULL);
	rbtree_clear(&db->icmp.tree4, release_bib_entry, NULL);

	pktqueue_destroy(db->tcp.pkt_queue);

	wkfree(struct bib, db);
}

void bib_put(struct bib *db)
{
	kref_put(&db->refs, release_bib);
}

void bib_config_copy(struct bib *db, struct bib_config *config)
{
	spin_lock_bh(&db->tcp.lock);
	config->bib_logging = db->tcp.log_bibs;
	config->session_logging = db->tcp.log_sessions;
	config->drop_by_addr = db->tcp.drop_by_addr;
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
	db->tcp.log_bibs = config->bib_logging;
	db->tcp.log_sessions = config->session_logging;
	db->tcp.drop_by_addr = config->drop_by_addr;
	db->tcp.est_timer.timeout = config->ttl.tcp_est;
	db->tcp.trans_timer.timeout = config->ttl.tcp_trans;
	db->tcp.pkt_limit = config->max_stored_pkts;
	db->tcp.drop_v4_syn = config->drop_external_tcp;
	spin_unlock_bh(&db->tcp.lock);

	spin_lock_bh(&db->udp.lock);
	db->udp.log_bibs = config->bib_logging;
	db->udp.log_sessions = config->session_logging;
	db->udp.drop_by_addr = config->drop_by_addr;
	db->udp.est_timer.timeout = config->ttl.udp;
	spin_unlock_bh(&db->udp.lock);

	spin_lock_bh(&db->icmp.lock);
	db->icmp.log_bibs = config->bib_logging;
	db->icmp.log_sessions = config->session_logging;
	db->icmp.est_timer.timeout = config->ttl.icmp;
	spin_unlock_bh(&db->icmp.lock);
}

static void log_bib(struct bib_table *table,
		struct tabled_bib *bib,
		char *action)
{
	struct timeval tval;
	struct tm t;

	if (!table->log_bibs)
		return;

	do_gettimeofday(&tval);
	time_to_tm(tval.tv_sec, 0, &t);
	log_info("%ld/%d/%d %d:%d:%d (GMT) - %s %pI6c#%u to %pI4#%u (%s)",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec, action,
			&bib->src6.l3, bib->src6.l4,
			&bib->src4.l3, bib->src4.l4,
			l4proto_to_string(bib->proto));
}

static void log_new_bib(struct bib_table *table, struct tabled_bib *bib)
{
	return log_bib(table, bib, "Mapped");
}

static void log_session(struct bib_table *table,
		struct tabled_session *session,
		char *action)
{
	struct timeval tval;
	struct tm t;

	if (!table->log_sessions)
		return;

	do_gettimeofday(&tval);
	time_to_tm(tval.tv_sec, 0, &t);
	log_info("%ld/%d/%d %d:%d:%d (GMT) - %s %pI6c#%u|%pI6c#%u|"
			"%pI4#%u|%pI4#%u|%s",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec, action,
			&session->bib->src6.l3, session->bib->src6.l4,
			&session->dst6.l3, session->dst6.l4,
			&session->bib->src4.l3, session->bib->src4.l4,
			&session->dst4.l3, session->dst4.l4,
			l4proto_to_string(session->bib->proto));
}

static void log_new_session(struct bib_table *table,
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
static void handle_probe(struct bib_table *table,
		struct list_head *probes,
		struct tabled_session *session,
		struct session_entry *tmp)
{
	struct probing_session *probe;

	if (WARN(!probes, "Probe needed but caller doesn't support it"))
		goto discard_probe;

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
		goto discard_probe;

	probe->session = *tmp;
	if (session->stored) {
		probe->skb = session->stored;
		session->stored = NULL;
		table->pkt_count--;
	} else {
		probe->skb = NULL;
	}
	list_add(&probe->list_hook, probes);
	return;

discard_probe:
	/*
	 * We're going to have to pretend that we sent it anyway; a probe
	 * failure should not prevent the state from evolving from V4 INIT and
	 * we do not want that massive thing to linger in the database anymore,
	 * especially if we failed due to a memory allocation.
	 */
	kill_stored_pkt(table, session);
}

static void rm(struct bib_table *table,
		struct list_head *probes,
		struct tabled_session *session,
		struct session_entry *tmp)
{
	struct tabled_bib *bib = session->bib;

	if (session->stored)
		handle_probe(table, probes, session, tmp);

	rb_erase(&session->tree_hook, &bib->sessions);
	list_del(&session->list_hook);
	log_session(table, session, "Forgot session");
	free_session(session);
	table->session_count--;

	if (!bib->is_static && RB_EMPTY_ROOT(&bib->sessions)) {
		rb_erase(&bib->hook6, &table->tree6);
		rb_erase(&bib->hook4, &table->tree4);
		log_bib(table, bib, "Forgot");
		free_bib(bib);
		table->bib_count--;
	}
}

static void handle_fate_timer(struct tabled_session *session,
		struct expire_timer *timer)
{
	session->update_time = jiffies;
	session->expirer = timer;
	list_del(&session->list_hook);
	list_add_tail(&session->list_hook, &timer->sessions);
}

static int queue_unsorted_session(struct bib_table *table,
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
		struct bib_table *table,
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
	if (!tmp.has_stored)
		kill_stored_pkt(table, session);
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
		if (probe->skb) {
			/* The "probe" is not a probe; it's an ICMP error. */
			icmp64_send_skb(probe->skb, ICMPERR_PORT_UNREACHABLE, 0);
			kfree_skb(probe->skb);
		} else {
			/* Actual TCP probe. */
			send_probe_packet(ns, &probe->session);
		}
		wkfree(struct probing_session, probe);
	}
}

struct slot_group {
	struct tree_slot bib6;
	struct tree_slot bib4;
	struct tree_slot session;
};

static void commit_bib_add(struct bib_table *table, struct slot_group *slots)
{
	treeslot_commit(&slots->bib6);
	treeslot_commit(&slots->bib4);
	table->bib_count++;
}

static void commit_session_add(struct bib_table *table, struct tree_slot *slot)
{
	treeslot_commit(slot);
	table->session_count++;
}

static void attach_timer(struct tabled_session *session,
		struct expire_timer *expirer)
{
	session->update_time = jiffies;
	session->expirer = expirer;
	list_add_tail(&session->list_hook, &expirer->sessions);
}

static int compare_src6(struct tabled_bib *a, struct ipv6_transport_addr *b)
{
	return taddr6_compare(&a->src6, b);
}

static int compare_src6_rbnode(struct rb_node *a, struct rb_node *b)
{
	return taddr6_compare(&bib6_entry(a)->src6, &bib6_entry(b)->src6);
}

static int compare_src4(struct tabled_bib const *a,
		struct ipv4_transport_addr const *b)
{
	return taddr4_compare(&a->src4, b);
}

static int compare_src4_rbnode(struct rb_node *a, struct rb_node *b)
{
	return taddr4_compare(&bib4_entry(a)->src4, &bib4_entry(b)->src4);
}

static int compare_dst4(struct tabled_session *a, struct tabled_session *b)
{
	return taddr4_compare(&a->dst4, &b->dst4);
}

static struct tabled_bib *find_bib6(struct bib_table *table,
		struct ipv6_transport_addr *addr)
{
	return rbtree_find(addr, &table->tree6, compare_src6, struct tabled_bib,
			hook6);
}

static struct tabled_bib *find_bib4(struct bib_table *table,
		struct ipv4_transport_addr *addr)
{
	return rbtree_find(addr, &table->tree4, compare_src4, struct tabled_bib,
			hook4);
}

static struct tabled_bib *find_bibtree6_slot(struct bib_table *table,
		struct tabled_bib *new,
		struct tree_slot *slot)
{
	struct rb_node *collision;
	collision = rbtree_find_slot(&new->hook6, &table->tree6,
			compare_src6_rbnode, slot);
	return bib6_entry(collision);
}

static struct tabled_bib *find_bibtree4_slot(struct bib_table *table,
		struct tabled_bib *new,
		struct tree_slot *slot)
{
	struct rb_node *collision;
	collision = rbtree_find_slot(&new->hook4, &table->tree4,
			compare_src4_rbnode, slot);
	return bib4_entry(collision);
}

/**
 * Attempts to find the slot where @new would be inserted if you wanted to add
 * it to @bib's session tree.
 *
 * On success:
 * - Initializes @slots as the place (in @bib's session tree) where @new would
 *   be inserted if you wanted to do so.
 * - Returns NULL.
 *
 * If @session collides with @bib's session S:
 * - @slot is undefined.
 * - S is returned.
 *
 * As a side effect, @allow will tell you whether the entry is allowed to be
 * added to the tree if address-dependent filtering is enabled. Send NULL if you
 * don't care about that.
 *
 * Please notice: This searches via @new's dst4, *not* dst6. @new *must* carry
 * an initialized dst4.
 */
static struct tabled_session *find_session_slot(struct tabled_bib *bib,
		struct tabled_session *new,
		bool *allow,
		struct tree_slot *slot)
{
	struct tabled_session *session;
	struct rb_node *node;
	int comparison;

	treeslot_init(slot, &bib->sessions, &new->tree_hook);
	node = bib->sessions.rb_node;
	if (allow)
		*allow = false;

	while (node) {
		session = node2session(node);
		comparison = compare_dst4(session, new);

		if (allow && session->dst4.l3.s_addr == new->dst4.l3.s_addr)
			*allow = true;

		slot->parent = node;
		if (comparison < 0) {
			slot->rb_link = &node->rb_right;
			node = node->rb_right;
		} else if (comparison > 0) {
			slot->rb_link = &node->rb_left;
			node = node->rb_left;
		} else {
			return session;
		}
	}

	return NULL;
}

static int alloc_bib_session(struct bib_session_tuple *tuple)
{
	tuple->bib = alloc_bib(GFP_ATOMIC);
	if (!tuple->bib)
		return -ENOMEM;

	tuple->session = alloc_session(GFP_ATOMIC);
	if (!tuple->session) {
		free_bib(tuple->bib);
		return -ENOMEM;
	}

	return 0;
}

static int create_bib_session6(struct bib_session_tuple *tuple,
		struct tuple *tuple6,
		struct ipv4_transport_addr *dst4,
		tcp_state state)
{
	int error;

	error = alloc_bib_session(tuple);
	if (error)
		return error;

	/*
	 * Hooks, expirer fields and session->bib are left uninitialized since
	 * they depend on database knowledge.
	 */

	tuple->bib->src6 = tuple6->src.addr6;
	/*
	 * src4 is left uninitialized on purpose.
	 * It needs to be inferred later by comparing the masks and the existing
	 * BIB entries.
	 */
	tuple->bib->proto = tuple6->l4_proto;
	tuple->bib->is_static = false;
	tuple->bib->sessions = RB_ROOT;
	tuple->session->dst6 = tuple6->dst.addr6;
	tuple->session->dst4 = *dst4;
	tuple->session->state = state;
	tuple->session->stored = NULL;
	return 0;
}

static struct tabled_session *create_session4(struct tuple *tuple4,
		struct ipv6_transport_addr *dst6,
		tcp_state state)
{
	struct tabled_session *session;

	session = alloc_session(GFP_ATOMIC);
	if (!session)
		return NULL;

	/*
	 * Hooks, expirer fields and session->bib are left uninitialized since
	 * they depend on database knowledge.
	 */
	session->dst6 = *dst6;
	session->dst4 = tuple4->src.addr4;
	session->state = state;
	session->stored = NULL;
	return session;
}

static int create_bib_session(struct session_entry *session,
		struct bib_session_tuple *tuple)
{
	int error;

	error = alloc_bib_session(tuple);
	if (error)
		return error;

	/*
	 * Hooks, most expirer fields and session->bib are left uninitialized
	 * since they depend on database knowledge.
	 */
	tuple->bib->src6 = session->src6;
	tuple->bib->src4 = session->src4;
	tuple->bib->proto = session->proto;
	tuple->bib->is_static = false;
	tuple->bib->sessions = RB_ROOT;
	tuple->session->dst6 = session->dst6;
	tuple->session->dst4 = session->dst4;
	tuple->session->state = session->state;
	tuple->session->update_time = session->update_time;
	tuple->session->stored = NULL;
	return 0;
}

/**
 * Boilerplate code to finish hanging @new->session (and potentially @new->bib
 * as well) on one af @table's trees. 6-to-4 direction.
 *
 * It assumes @slots already describes the tree containers where the entries are
 * supposed to be added.
 */
static void commit_add6(struct bib_table *table,
		struct bib_session_tuple *old,
		struct bib_session_tuple *new,
		struct slot_group *slots,
		struct expire_timer *expirer,
		struct bib_session *result)
{
	new->session->bib = old->bib ? : new->bib;
	commit_session_add(table, &slots->session);
	attach_timer(new->session, expirer);
	log_new_session(table, new->session);
	tstobs(new->session, result);
	new->session = NULL; /* Do not free! */

	if (!old->bib) {
		commit_bib_add(table, slots);
		log_new_bib(table, new->bib);
		new->bib = NULL; /* Do not free! */
	}
}

/**
 * Boilerplate code to finish hanging *@new on one af @table's trees.
 * 4-to-6 direction.
 *
 * It assumes @slot already describes the tree container where the session is
 * supposed to be added.
 */
static void commit_add4(struct bib_table *table,
		struct bib_session_tuple *old,
		struct tabled_session **new,
		struct tree_slot *slot,
		struct expire_timer *expirer,
		struct bib_session *result)
{
	struct tabled_session *session = *new;

	session->bib = old->bib;
	commit_session_add(table, slot);
	attach_timer(session, expirer);
	log_new_session(table, session);
	tstobs(session, result);
	*new = NULL; /* Do not free! */
}

/**
 * Boilerplate code to finish hanging *@new on one af @table's trees.
 * joold version.
 *
 * It assumes @slots already describes the tree containers where the entries are
 * supposed to be added.
 */
static int commit_add(struct bib_table *table,
		struct bib_session_tuple *old,
		struct bib_session_tuple *new,
		struct slot_group *slots,
		session_timer_type timer_type)
{
	int error;

	error = queue_unsorted_session(table, new->session, timer_type, false);
	if (error)
		return error;

	new->session->bib = old->bib ? : new->bib;
	commit_session_add(table, &slots->session);
	log_new_session(table, new->session);
	new->session = NULL; /* Do not free! */

	if (!old->bib) {
		commit_bib_add(table, slots);
		log_new_bib(table, new->bib);
		new->bib = NULL; /* Do not free! */
	}

	return 0;
}

struct detach_args {
	struct bib_table *table;
	struct sk_buff *probes;
	unsigned int detached;
};

static void detach_session(struct rb_node *node, void *arg)
{
	struct tabled_session *session = node2session(node);
	struct detach_args *args = arg;

	list_del(&session->list_hook);
	if (session->stored)
		args->table->pkt_count--;
	args->detached++;
}

static unsigned int detach_sessions(struct bib_table *table,
		struct tabled_bib *bib)
{
	struct detach_args arg = { .table = table, .detached = 0, };
	rbtree_foreach(&bib->sessions, detach_session, &arg);
	return arg.detached;
}

static void detach_bib(struct bib_table *table, struct tabled_bib *bib)
{
	rb_erase(&bib->hook6, &table->tree6);
	rb_erase(&bib->hook4, &table->tree4);
	table->bib_count--;
	table->session_count -= detach_sessions(table, bib);
}

struct bib_delete_list {
	struct rb_node *first;
};

static void add_to_delete_list(struct bib_delete_list *list, struct rb_node *node)
{
	node->rb_right = list->first;
	list->first = node;
}

static void commit_delete_list(struct bib_delete_list *list)
{
	struct rb_node *node;
	struct rb_node *next;

	for (node = list->first; node; node = next) {
		next = node->rb_right;
		release_bib_entry(node, NULL);
	}
}

/**
 * Tests whether @predecessor's immediate succesor tree slot is a suitable
 * placeholder for @bib. Returns the colliding node.
 *
 * (That is, returns NULL on success, a collision on failure.)
 *
 * In other words:
 * Assumes that @predecessor belongs to @table's v4 tree and that it is @bib's
 * predecessor. (ie. @predecessor's transport address is @bib's transport
 * address - 1.) You want to test whether @bib can be inserted to the tree.
 * If @predecessor's succesor collides with @bib (ie. it has @bib's v4 address),
 * it returns the colliding succesor.
 * If @predecessor's succesor does not collide with @bib, it returns NULL and
 * initializes @slot so you can actually add @bib to the tree.
 */
static struct tabled_bib *try_next(struct bib_table *table,
		struct tabled_bib *predecessor,
		struct tabled_bib *bib,
		struct tree_slot *slot)
{
	struct tabled_bib *next;

	next = bib4_entry(rb_next(&predecessor->hook4));
	if (!next) {
		/* There is no succesor and therefore no collision. */
		slot->tree = &table->tree4;
		slot->entry = &bib->hook4;
		slot->parent = &predecessor->hook4;
		slot->rb_link = &slot->parent->rb_right;
		return NULL;
	}

	if (taddr4_equals(&next->src4, &bib->src4))
		return next; /* Next is yet another collision. */

	slot->tree = &table->tree4;
	slot->entry = &bib->hook4;
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
 * 		if (mask is not taken by an existing BIB entry from @table)
 * 			init the new BIB entry, @bib, using mask
 * 			init @slot as the tree slot where @bib should be added
 * 			return success (0)
 * 	return failure (-ENOENT)
 *
 */
static int find_available_mask(struct bib_table *table,
		struct mask_domain *masks,
		struct tabled_bib *bib,
		struct tree_slot *slot)
{
	struct tabled_bib *collision = NULL;
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
		error = mask_domain_next(masks, &bib->src4, &consecutive);
		if (error)
			return error;

		/*
		 * Just for the sake of clarity:
		 * @consecutive is never true on the first iteration.
		 */
		collision = consecutive
				? try_next(table, collision, bib, slot)
				: find_bibtree4_slot(table, bib, slot);
	} while (collision);

	return 0;
}

static int upgrade_pktqueue_session(struct bib_table *table,
		struct mask_domain *masks,
		struct bib_session_tuple *new,
		struct bib_session_tuple *old)
{
	struct pktqueue_session *sos; /* "simultaneous open" session */
	struct tabled_bib *bib;
	struct tabled_bib *collision;
	struct tabled_session *session;
	struct tree_slot bib_slot6;
	struct tree_slot bib_slot4;
	int error;

	if (new->bib->proto != L4PROTO_TCP)
		return -ESRCH;

	sos = pktqueue_find(table->pkt_queue, &new->session->dst6, masks);
	if (!sos)
		return -ESRCH;
	table->pkt_count--;

	if (!masks) {
		/*
		 * This happens during joold adds. It's a lost cause.
		 *
		 * The point of SO is that the v4 node decides session [*, dst6,
		 * src4, dst4] and the first v6 packet needing a new mask that
		 * matches that session keeps it.
		 *
		 * But we're not synchronizing pktqueue sessions, because we
		 * want to keep joold as simple as possible (which is not simple
		 * enough), at least so long as it remains a niche thing.
		 *
		 * So if one Jool instance gets the v4 SO packet and some other
		 * instance gets the v6 SO packet, the latter will choose a
		 * random src4 and mess up the SO. That situation is this if.
		 * Our reaction is to go like "whatever" and pretend that we
		 * never received the v4 packet.
		 *
		 * One might argue that we should send the ICMP error when this
		 * happens. But that doesn't yield satisfactory behavior either;
		 * The SO failed anyway. To fix this properly we would need to
		 * sync the pktqueue sessions. Combine that with the fact that
		 * sending the ICMP error would be a pain in the ass (because we
		 * want to do it outside of the spinlock, and we don't want to
		 * send it if the random src4 selected happens to match the
		 * stored session), and the result is a big fat meh. I really
		 * don't want to do it.
		 *
		 * The admin signed a best-effort contract when s/he enabled
		 * joold anyway. And this is only a problem in active-active
		 * scenarios.
		 */
		pktqueue_put_node(sos);
		return -ESRCH;
	}

	log_debug("Simultaneous Open!");
	/*
	 * We're going to pretend that @sos has been a valid V4 INIT session all
	 * along.
	 */
	error = alloc_bib_session(old);
	if (error) {
		pktqueue_put_node(sos);
		return error;
	}

	bib = old->bib;
	session = old->session;

	bib->src6 = new->bib->src6;
	bib->src4 = sos->src4;
	bib->proto = L4PROTO_TCP;
	bib->is_static = false;
	bib->sessions = RB_ROOT;

	session->dst6 = sos->dst6;
	session->dst4 = sos->dst4;
	session->state = V4_INIT;
	session->bib = bib;
	session->update_time = jiffies;
	session->stored = NULL;

	/*
	 * This *has* to work. src6 wasn't in the database because we just
	 * looked it up and src4 wasn't either because pktqueue had it.
	 */
	collision = find_bibtree6_slot(table, bib, &bib_slot6);
	if (WARN(collision, "BIB entry was and then wasn't in the v6 tree."))
		goto trainwreck;
	collision = find_bibtree4_slot(table, bib, &bib_slot4);
	if (WARN(collision, "BIB entry was and then wasn't in the v4 tree."))
		goto trainwreck;
	treeslot_commit(&bib_slot6);
	treeslot_commit(&bib_slot4);

	rb_link_node(&session->tree_hook, NULL, &bib->sessions.rb_node);
	rb_insert_color(&session->tree_hook, &bib->sessions);
	attach_timer(session, &table->syn4_timer);

	pktqueue_put_node(sos);

	log_new_bib(table, bib);
	log_new_session(table, session);
	return 0;

trainwreck:
	pktqueue_put_node(sos);
	free_bib(bib);
	free_session(session);
	return -EINVAL;
}

static bool issue216_needed(struct mask_domain *masks,
		struct bib_session_tuple *old)
{
	if (!masks)
		return false;
	return mask_domain_is_dynamic(masks)
			&& !mask_domain_matches(masks, &old->bib->src4);
}

/**
 * This is a find and an add at the same time, for both @new->bib and
 * @new->session.
 *
 * If @new->bib needs to be added, initializes @slots->bib*.
 * If @new->session needs to be added, initializes @slots->session.
 * If @new->bib collides, you will find the collision in @old->bib.
 * If @new->session collides, you will find the collision in @old->session.
 *
 * @masks will be used to init @new->bib.src4 if applies.
 */
static int find_bib_session6(struct bib_table *table,
		struct mask_domain *masks,
		struct bib_session_tuple *new,
		struct bib_session_tuple *old,
		struct slot_group *slots,
		struct bib_delete_list *rm_list)
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

	old->bib = find_bibtree6_slot(table, new->bib, &slots->bib6);
	if (old->bib) {
		if (!issue216_needed(masks, old)) {
			if (new->bib->proto == L4PROTO_ICMP)
				new->session->dst4.l4 = old->bib->src4.l4;

			old->session = find_session_slot(old->bib, new->session,
					NULL, &slots->session);
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
		detach_bib(table, old->bib);
		add_to_delete_list(rm_list, &old->bib->hook4);

		/*
		 * The detaching above might have involved a rebalance.
		 * I believe that completely invalidates the bib6 slot.
		 * Tough luck; we'll need another lookup.
		 * At least this only happens on empty pool4s. (Low traffic.)
		 */
		old->bib = find_bibtree6_slot(table, new->bib, &slots->bib6);
		if (WARN(old->bib, "Found a BIB entry I just removed!"))
			return -EINVAL;

	} else {
		/*
		 * No BIB nor session in the main database? Try the SO
		 * sub-database.
		 */
		error = upgrade_pktqueue_session(table, masks, new, old);
		if (!error)
			return 0; /* Unusual happy path for existing sessions */
	}

	/*
	 * In case you're tweaking this function: By this point, old->bib has to
	 * be NULL and slots->bib6 has to be a valid potential tree slot. We're
	 * now in create-new-BIB-and-session mode.
	 * Time to worry about slots->bib4.
	 *
	 * (BTW: If old->bib is NULL, then old->session is also supposed to be
	 * NULL.)
	 */
	if (masks) {
		error = find_available_mask(table, masks, new->bib, &slots->bib4);
		if (error) {
			if (WARN(error != -ENOENT, "Unknown error: %d", error))
				return error;
			log_warn_once("I ran out of pool4 addresses.");
			return error;
		}

		if (new->bib->proto == L4PROTO_ICMP)
			new->session->dst4.l4 = new->bib->src4.l4;

	} else {
		/*
		 * TODO (issue113) perhaps the sender's session shold be trusted
		 * more.
		 */
		if (find_bibtree4_slot(table, new->bib, &slots->bib4))
			return -EEXIST;
	}

	/* Ok, time to worry about slots->session now. */

	treeslot_init(&slots->session, &new->bib->sessions,
			&new->session->tree_hook);
	old->session = NULL;

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
	struct bib_table *table;
	struct bib_session_tuple new;
	struct bib_session_tuple old;
	struct slot_group slots;
	struct bib_delete_list rm_list = { NULL };
	int error;

	table = get_table(db, tuple6->l4_proto);
	if (!table)
		return -EINVAL;

	/*
	 * We might have a lot to do. This function may index three RB-trees
	 * so spinlock time is tight.
	 *
	 * (That's 3 potential lookups (2 guaranteed) and 3 potential
	 * rebalances, though at least one of the trees is usually minuscule.)
	 *
	 * There's also the optional port allocation thing, which in the worst
	 * case is an unfortunate full traversal of @masks.
	 *
	 * Let's start by allocating and initializing the objects as much as we
	 * can, even if we end up not needing them.
	 */
	error = create_bib_session6(&new, tuple6, dst4, ESTABLISHED);
	if (error)
		return error;

	spin_lock_bh(&table->lock); /* Here goes... */

	error = find_bib_session6(table, masks, &new, &old, &slots, &rm_list);
	if (error)
		goto end;

	if (old.session) { /* Session already exists. */
		handle_fate_timer(old.session, &table->est_timer);
		tstobs(old.session, result);
		goto end;
	}

	/* New connection; add the session. (And maybe the BIB entry as well) */
	commit_add6(table, &old, &new, &slots, &table->est_timer, result);
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new.bib)
		free_bib(new.bib);
	if (new.session)
		free_session(new.session);
	commit_delete_list(&rm_list);

	return error;
}

static void find_bib_session4(struct bib_table *table,
		struct tuple *tuple4,
		struct tabled_session *new,
		struct bib_session_tuple *old,
		bool *allow,
		struct tree_slot *slot)
{
	old->bib = find_bib4(table, &tuple4->dst.addr4);
	old->session = old->bib
			? find_session_slot(old->bib, new, allow, slot)
			: NULL;
}

/**
 * See @bib_add6.
 */
int bib_add4(struct bib *db,
		struct ipv6_transport_addr *dst6,
		struct tuple *tuple4,
		struct bib_session *result)
{
	struct bib_table *table;
	struct bib_session_tuple old;
	struct tabled_session *new;
	struct tree_slot session_slot;
	bool allow;
	int error = 0;

	table = get_table(db, tuple4->l4_proto);
	if (!table)
		return -EINVAL;

	new = create_session4(tuple4, dst6, ESTABLISHED);
	if (!new)
		return -ENOMEM;

	spin_lock_bh(&table->lock);

	find_bib_session4(table, tuple4, new, &old, &allow, &session_slot);

	if (old.session) {
		handle_fate_timer(old.session, &table->est_timer);
		tstobs(old.session, result);
		goto end;
	}

	if (!old.bib) {
		error = -ESRCH;
		goto end;
	}

	/* Address-Dependent Filtering. */
	if (table->drop_by_addr && !allow) {
		error = -EPERM;
		goto end;
	}

	/* Ok, no issues; add the session. */
	commit_add4(table, &old, &new, &session_slot, &table->est_timer, result);
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);
	if (new)
		free_session(new);
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
	struct bib_table *table;
	struct bib_session_tuple new;
	struct bib_session_tuple old;
	struct slot_group slots;
	struct bib_delete_list rm_list = { NULL };
	verdict verdict;

	if (WARN(pkt->tuple.l4_proto != L4PROTO_TCP, "Incorrect l4 proto in TCP handler."))
		return VERDICT_DROP;

	if (create_bib_session6(&new, &pkt->tuple, dst4, V6_INIT))
		return VERDICT_DROP;

	table = &db->tcp;
	spin_lock_bh(&table->lock);

	if (find_bib_session6(table, masks, &new, &old, &slots, &rm_list)) {
		verdict = VERDICT_DROP;
		goto end;
	}

	if (old.session) {
		/* All states except CLOSED. */
		verdict = decide_fate(cb, table, old.session, NULL);
		if (verdict == VERDICT_CONTINUE)
			tstobs(old.session, result);
		goto end;
	}

	/* CLOSED state beginning now. */

	if (!pkt_tcp_hdr(pkt)->syn) {
		if (old.bib) {
			tbtobs(old.bib, result);
			verdict = VERDICT_CONTINUE;
		} else {
			log_debug("Packet is not SYN and lacks state.");
			verdict = VERDICT_DROP;
		}
		goto end;
	}

	/* All exits up till now require @new.* to be deleted. */

	commit_add6(table, &old, &new, &slots, &table->trans_timer, result);
	verdict = VERDICT_CONTINUE;
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new.bib)
		free_bib(new.bib);
	if (new.session)
		free_session(new.session);
	commit_delete_list(&rm_list);

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
	struct bib_table *table;
	struct tabled_session *new;
	struct bib_session_tuple old;
	struct tree_slot session_slot;
	verdict verdict;
	int error;

	if (WARN(pkt->tuple.l4_proto != L4PROTO_TCP, "Incorrect l4 proto in TCP handler."))
		return VERDICT_DROP;

	new = create_session4(&pkt->tuple, dst6, V4_INIT);
	if (!new)
		return VERDICT_DROP;

	table = &db->tcp;
	spin_lock_bh(&table->lock);

	find_bib_session4(table, &pkt->tuple, new, &old, NULL, &session_slot);

	if (old.session) {
		/* All states except CLOSED. */
		verdict = decide_fate(cb, table, old.session, NULL);
		if (verdict == VERDICT_CONTINUE)
			tstobs(old.session, result);
		goto end;
	}

	/* CLOSED state beginning now. */

	if (!pkt_tcp_hdr(pkt)->syn) {
		if (old.bib) {
			tbtobs(old.bib, result);
			verdict = VERDICT_CONTINUE;
		} else {
			log_debug("Packet is not SYN and lacks state.");
			verdict = VERDICT_DROP;
		}
		goto end;
	}

	if (table->drop_v4_syn) {
		log_debug("Externally initiated TCP connections are prohibited.");
		verdict = VERDICT_DROP;
		goto end;
	}

	if (!old.bib) {
		bool too_many;

		log_debug("Potential Simultaneous Open; storing type 1 packet.");
		too_many = table->pkt_count >= table->pkt_limit;
		error = pktqueue_add(table->pkt_queue, pkt, dst6, too_many);
		switch (error) {
		case 0:
			verdict = VERDICT_STOLEN;
			table->pkt_count++;
			goto end;
		case -EEXIST:
			log_debug("Simultaneous Open already exists.");
			break;
		case -ENOSPC:
			goto too_many_pkts;
		case -ENOMEM:
			break;
		default:
			WARN(1, "pktqueue_add() threw unknown error %d", error);
			break;
		}

		verdict = VERDICT_DROP;
		goto end;
	}

	verdict = VERDICT_CONTINUE;

	if (table->drop_by_addr) {
		if (table->pkt_count >= table->pkt_limit)
			goto too_many_pkts;

		log_debug("Potential Simultaneous Open; storing type 2 packet.");
		new->stored = pkt_original_pkt(pkt)->skb;
		verdict = VERDICT_STOLEN;
		table->pkt_count++;
		/*
		 * Yes, fall through. No goto; we need to add this session.
		 * Notice that if you need to cancel before the spin unlock then
		 * you need to revert the packet storing above.
		 */
	}

	commit_add4(table, &old, &new, &session_slot,
			new->stored ? &table->syn4_timer : &table->trans_timer,
			result);
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new)
		free_session(new);

	return verdict;

too_many_pkts:
	spin_unlock_bh(&table->lock);
	free_session(new);
	log_debug("Too many Simultaneous Opens.");
	/* Fall back to assume there's no SO. */
	icmp64_send(pkt, ICMPERR_PORT_UNREACHABLE, 0);
	return VERDICT_DROP;
}

int bib_find(struct bib *db, struct tuple *tuple, struct bib_session *result)
{
	struct bib_entry tmp;
	int error;

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		error = bib_find6(db, tuple->l4_proto, &tuple->src.addr6, &tmp);
		break;
	case L3PROTO_IPV4:
		error = bib_find4(db, tuple->l4_proto, &tuple->dst.addr4, &tmp);
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
	struct bib_table *table;
	struct bib_session_tuple new;
	struct bib_session_tuple old;
	struct slot_group slots;
	struct bib_delete_list rm_list = { NULL };
	int error;

	table = get_table(db, session->proto);
	if (!table)
		return -EINVAL;

	error = create_bib_session(session, &new);
	if (error)
		return error;

	spin_lock_bh(&table->lock);

	error = find_bib_session6(table, NULL, &new, &old, &slots, &rm_list);
	if (error)
		goto end;

	if (old.session) {
		/* There's no packet; ignore the verdict. */
		decide_fate(cb, table, old.session, NULL);
		goto end;
	}

	error = commit_add(table, &old, &new, &slots, session->timer_type);
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new.bib)
		free_bib(new.bib);
	if (new.session)
		free_session(new.session);
	commit_delete_list(&rm_list);

	return error;
}

static void __clean(struct expire_timer *expirer,
		struct bib_table *table,
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

static void clean_table(struct bib_table *table, struct net *ns)
{
	LIST_HEAD(probes);
	LIST_HEAD(icmps);

	spin_lock_bh(&table->lock);
	__clean(&table->est_timer, table, &probes);
	__clean(&table->trans_timer, table, &probes);
	__clean(&table->syn4_timer, table, &probes);
	if (table->pkt_queue) {
		table->pkt_count -= pktqueue_prepare_clean(table->pkt_queue,
				&icmps);
	}
	spin_unlock_bh(&table->lock);

	post_fate(ns, &probes);
	pktqueue_clean(&icmps);
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

static struct rb_node *find_starting_point(struct bib_table *table,
		const struct ipv4_transport_addr *offset,
		bool include_offset)
{
	struct tabled_bib *bib;
	struct rb_node **node;
	struct rb_node *parent;

	/* If there's no offset, start from the beginning. */
	if (!offset)
		return rb_first(&table->tree4);

	/* If offset is found, start from offset or offset's next. */
	rbtree_find_node(offset, &table->tree4, compare_src4, struct tabled_bib,
			hook4, parent, node);
	if (*node)
		return include_offset ? (*node) : rb_next(*node);

	if (!parent)
		return NULL;

	/*
	 * If offset is not found, start from offset's next anyway.
	 * (If offset was meant to exist, it probably timed out and died while
	 * the caller wasn't holding the spinlock; it's nothing to worry about.)
	 */
	bib = rb_entry(parent, struct tabled_bib, hook4);
	return (compare_src4(bib, offset) < 0) ? rb_next(parent) : parent;
}

int bib_foreach(struct bib *db, l4_protocol proto,
		struct bib_foreach_func *func,
		const struct ipv4_transport_addr *offset)
{
	struct bib_table *table;
	struct rb_node *node;
	struct tabled_bib *tabled;
	struct bib_entry bib;
	int error = 0;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);

	node = find_starting_point(table, offset, false);
	for (; node && !error; node = rb_next(node)) {
		tabled = bib4_entry(node);
		tbtobe(tabled, &bib);
		error = func->cb(&bib, tabled->is_static, func->arg);
	}

	spin_unlock_bh(&table->lock);
	return error;
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

static void next_bib(struct rb_node *next, struct bib_session_tuple *pos)
{
	pos->bib = bib4_entry(next);
}

static void next_session(struct rb_node *next, struct bib_session_tuple *pos)
{
	pos->session = node2session(next);
	if (!pos->session) {
		/* Tree was empty or the previous was the last session. */
		/* Cascade "next" to the supertree. */
		next_bib(rb_next(&pos->bib->hook4), pos);
	}
}

/**
 * Finds the BIB entry and/or session where a foreach of the sessions should
 * start with, based on @offset.
 *
 * If a session that matches @offset is found, will initialize both @pos->bib
 * and @pos->session to point to this session.
 * If @pos->bib is defined but @pos->session is not, the foreach should start
 * from @pos->bib's first session.
 * If neither @pos->bib nor @pos->session are defined, iteration ended.
 * (offset lies after the last session.)
 *
 * If @offset is not found, it always tries to return the session that would
 * follow one that would match perfectly. This is because sessions expiring
 * during ongoing fragmented foreaches are not considered a problem.
 */
static void find_session_offset(struct bib_table *table,
		struct session_foreach_offset *offset,
		struct bib_session_tuple *pos)
{
	struct tabled_bib tmp_bib;
	struct tabled_session tmp_session;
	struct tree_slot slot;

	memset(pos, 0, sizeof(*pos));

	tmp_bib.src4 = offset->offset.src;
	pos->bib = find_bibtree4_slot(table, &tmp_bib, &slot);
	if (!pos->bib) {
		next_bib(slot_next(&slot), pos);
		return;
	}

	tmp_session.dst4 = offset->offset.dst;
	pos->session = find_session_slot(pos->bib, &tmp_session, NULL, &slot);
	if (!pos->session) {
		next_session(slot_next(&slot), pos);
		return;
	}

	if (!offset->include_offset)
		next_session(rb_next(&pos->session->tree_hook), pos);
}

#define foreach_bib(table, node) \
		for (node = bib4_entry(rb_first(&(table)->tree4)); \
				node; \
				node = bib4_entry(rb_next(&node->hook4)))
#define foreach_session(tree, node) \
		for (node = node2session(rb_first(tree)); \
				node; \
				node = node2session(rb_next(&node->tree_hook)))

int bib_foreach_session(struct bib *db, l4_protocol proto,
		struct session_foreach_func *func,
		struct session_foreach_offset *offset)
{
	struct bib_table *table;
	struct bib_session_tuple pos;
	struct session_entry tmp;
	int error = 0;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);

	if (offset) {
		find_session_offset(table, offset, &pos);
		/* if pos.session != NULL, then pos.bib != NULL. */
		if (pos.session)
			goto goto_session;
		if (pos.bib)
			goto goto_bib;
		goto end;
	}

	foreach_bib(table, pos.bib) {
goto_bib:	foreach_session(&pos.bib->sessions, pos.session) {
goto_session:		tstose(pos.session, &tmp);
			error = func->cb(&tmp, func->arg);
			if (error)
				goto end;
		}
	}

end:
	spin_unlock_bh(&table->lock);
	return error;
}

#undef foreach_session
#undef foreach_bib

int bib_find6(struct bib *db, l4_protocol proto,
		struct ipv6_transport_addr *addr,
		struct bib_entry *result)
{
	struct bib_table *table;
	struct tabled_bib *bib;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	bib = find_bib6(table, addr);
	if (bib)
		tbtobe(bib, result);
	spin_unlock_bh(&table->lock);

	return bib ? 0 : -ESRCH;
}

int bib_find4(struct bib *db, l4_protocol proto,
		struct ipv4_transport_addr *addr,
		struct bib_entry *result)
{
	struct bib_table *table;
	struct tabled_bib *bib;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	bib = find_bib4(table, addr);
	if (bib)
		tbtobe(bib, result);
	spin_unlock_bh(&table->lock);

	return bib ? 0 : -ESRCH;
}

static void bib2tabled(struct bib_entry *bib, struct tabled_bib *tabled)
{
	tabled->src6 = bib->ipv6;
	tabled->src4 = bib->ipv4;
	tabled->proto = bib->l4_proto;
	tabled->is_static = true;
	tabled->sessions = RB_ROOT;
}

int bib_add_static(struct bib *db, struct bib_entry *new,
		struct bib_entry *old)
{
	struct bib_table *table;
	struct tabled_bib *bib;
	struct tabled_bib *collision;
	struct tree_slot slot6;
	struct tree_slot slot4;

	table = get_table(db, new->l4_proto);
	if (!table)
		return -EINVAL;

	bib = alloc_bib(GFP_ATOMIC);
	if (!bib)
		return -ENOMEM;
	bib2tabled(new, bib);

	spin_lock_bh(&table->lock);

	collision = find_bibtree6_slot(table, bib, &slot6);
	if (collision) {
		if (taddr4_equals(&bib->src4, &collision->src4))
			goto upgrade;
		goto eexist;
	}

	collision = find_bibtree4_slot(table, bib, &slot4);
	if (collision)
		goto eexist;

	treeslot_commit(&slot6);
	treeslot_commit(&slot4);
	table->bib_count++;

	/*
	 * Since the BIB entry is now available, and assuming ADF is disabled,
	 * it would make sense to translate the relevant type 1 stored packets.
	 * That's bound to be a lot of messy code though, and the v4 client is
	 * going to retry anyway, so let's just forget the packets instead.
	 */
	if (new->l4_proto == L4PROTO_TCP)
		pktqueue_rm(db->tcp.pkt_queue, &new->ipv4);

	spin_unlock_bh(&table->lock);
	return 0;

upgrade:
	collision->is_static = true;
	spin_unlock_bh(&table->lock);
	free_bib(bib);
	return 0;

eexist:
	tbtobe(collision, old);
	spin_unlock_bh(&table->lock);
	free_bib(bib);
	return -EEXIST;
}

int bib_rm(struct bib *db, struct bib_entry *entry)
{
	struct bib_table *table;
	struct tabled_bib key;
	struct tabled_bib *bib;
	int error = -ESRCH;

	table = get_table(db, entry->l4_proto);
	if (!table)
		return -EINVAL;

	bib2tabled(entry, &key);

	spin_lock_bh(&table->lock);

	bib = find_bib6(table, &key.src6);
	if (bib && taddr4_equals(&key.src4, &bib->src4)) {
		detach_bib(table, bib);
		error = 0;
	}

	spin_unlock_bh(&table->lock);

	if (!error)
		release_bib_entry(&bib->hook4, NULL);

	return error;
}

void bib_rm_range(struct bib *db, l4_protocol proto, struct ipv4_range *range)
{
	struct bib_table *table;
	struct ipv4_transport_addr offset;
	struct rb_node *node;
	struct rb_node *next;
	struct tabled_bib *bib;
	struct bib_delete_list delete_list = { NULL };

	table = get_table(db, proto);
	if (!table)
		return;

	offset.l3 = range->prefix.address;
	offset.l4 = range->ports.min;

	spin_lock_bh(&table->lock);

	node = find_starting_point(table, &offset, true);
	for (; node; node = next) {
		next = rb_next(node);
		bib = bib4_entry(node);

		if (!prefix4_contains(&range->prefix, &bib->src4.l3))
			break;
		if (port_range_contains(&range->ports, bib->src4.l4)) {
			detach_bib(table, bib);
			add_to_delete_list(&delete_list, node);
		}
	}

	spin_unlock_bh(&table->lock);

	commit_delete_list(&delete_list);
}

static void flush_table(struct bib_table *table)
{
	struct rb_node *node;
	struct rb_node *next;
	struct bib_delete_list delete_list = { NULL };

	spin_lock_bh(&table->lock);

	for (node = rb_first(&table->tree4); node; node = next) {
		next = rb_next(node);
		detach_bib(table, bib4_entry(node));
		add_to_delete_list(&delete_list, node);
	}

	spin_unlock_bh(&table->lock);

	commit_delete_list(&delete_list);
}

void bib_flush(struct bib *db)
{
	flush_table(&db->tcp);
	flush_table(&db->udp);
	flush_table(&db->icmp);
}

int bib_count(struct bib *db, l4_protocol proto, __u64 *count)
{
	struct bib_table *table;

	table = get_table(db, proto);
	if (!table)
		return -EINVAL;

	spin_lock_bh(&table->lock);
	*count = table->bib_count;
	spin_unlock_bh(&table->lock);
	return 0;
}

int bib_count_sessions(struct bib *db, l4_protocol proto, __u64 *count)
{
	struct bib_table *table;

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
	pr_info("[Ssn]");

	session = node2session(node);
	print_tabs(tabs);
	pr_cont("[%s] %pI4#%u %pI6c#%u\n", prefix,
			&session->dst4.l3, session->dst4.l4,
			&session->dst6.l3, session->dst6.l4);

	print_session(node->rb_left, tabs + 1, "L"); /* "Left" */
	print_session(node->rb_right, tabs + 1, "R"); /* "Right" */
}

static void print_bib(struct rb_node *node, int tabs)
{
	struct tabled_bib *bib;

	if (!node)
		return;
	pr_info("[BIB]");

	bib = bib4_entry(node);
	print_tabs(tabs);
	pr_cont("%pI4#%u %pI6c#%u\n", &bib->src4.l3, bib->src4.l4,
			&bib->src6.l3, bib->src6.l4);

	print_session(bib->sessions.rb_node, tabs + 1, "T"); /* "Tree" */
	print_bib(node->rb_left, tabs + 1);
	print_bib(node->rb_right, tabs + 1);
}

void bib_print(struct bib *db)
{
	log_debug("TCP:");
	print_bib(db->tcp.tree4.rb_node, 1);
	log_debug("UDP:");
	print_bib(db->udp.tree4.rb_node, 1);
	log_debug("ICMP:");
	print_bib(db->icmp.tree4.rb_node, 1);
}
