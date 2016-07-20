#include "nat64/mod/stateful/bib/db.h"

#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateful/bib/pkt_queue.h"

/*
 * TODO (performance) Pack this?
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
 * TODO (performance) Pack this?
 */
struct tabled_session {
	struct ipv6_transport_addr dst6;
	struct ipv4_transport_addr dst4;
	tcp_state state;
	struct tabled_bib *bib;

	struct rb_node tree_hook;
	/*
	 * TODO (performance) The UDP tree is the only one that needs this.
	 * Consider unifying the TCP and ICMP trees.
	 */
	struct rb_root subtree;

	unsigned long update_time;
	struct expire_timer *expirer;
	struct list_head list_hook;
};

struct bib_session_tuple {
	struct tabled_bib *bib;
	struct tabled_session *session;
};

struct probing_session {
	struct session_entry session;
	struct list_head list_hook;
};

struct expire_timer {
	struct list_head sessions;
	unsigned long timeout;
	bool is_established;
	fate_cb decide_fate_cb;
};

/**
 * BIB table definition.
 * Holds two red-black trees, one for each indexing need (IPv4 and IPv6).
 */
struct bib_table {
	/** Indexes the entries using their IPv6 identifiers. */
	struct rb_root tree6;
	/** Indexes the entries using their IPv4 identifiers. */
	struct rb_root tree4;

	/* Number of entries in this table. */
	u64 bib_count;
	u64 session_count;

	/** Expires this table's established sessions. */
	struct expire_timer est_timer;
	/** Expires this table's transitory sessions. */
	struct expire_timer trans_timer;

	/* Drop externally initiated TCP connections? */
	bool drop_v4_syn;
	/** Is Address-Dependent Filtering active? */
	bool drop_by_addr;
	/* Write BIB entries on the log as they are created and destroyed? */
	bool log_bibs;
	/* Write sessions on the log as they are created and destroyed? */
	bool log_sessions;

	spinlock_t lock;
};

struct bib {
	/** The session table for UDP conversations. */
	struct bib_table udp;
	/** The session table for TCP connections. */
	struct bib_table tcp;
	/** The session table for ICMP conversations. */
	struct bib_table icmp;

	/** Packet storage for simultaneous open of TCP connections. */
	struct pktqueue *pkt_queue;

	struct kref refs;
};

static struct kmem_cache *bib_cache;
static struct kmem_cache *session_cache;

static struct tabled_bib *bib6_entry(struct rb_node *node)
{
	return rb_entry(node, struct tabled_bib, hook6);
}

static struct tabled_bib *bib4_entry(struct rb_node *node)
{
	return rb_entry(node, struct tabled_bib, hook4);
}

static struct tabled_session *node2session(struct rb_node *node)
{
	return rb_entry(node, struct tabled_session, tree_hook);
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
	session->established = tsession->expirer->is_established;
	session->update_time = tsession->update_time;
	session->timeout = tsession->expirer->timeout;
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

static void init_table(struct bib_table *table, unsigned long est_timeout,
		unsigned long trans_timeout, fate_cb est_cb)
{
	table->tree6 = RB_ROOT;
	table->tree4 = RB_ROOT;
	table->bib_count = 0;
	table->session_count = 0;

	INIT_LIST_HEAD(&table->est_timer.sessions);
	table->est_timer.timeout = msecs_to_jiffies(1000 * est_timeout);
	table->est_timer.is_established = true;
	table->est_timer.decide_fate_cb = est_cb;

	INIT_LIST_HEAD(&table->trans_timer.sessions);
	table->trans_timer.timeout = msecs_to_jiffies(1000 * trans_timeout);
	table->trans_timer.is_established = false;
	table->trans_timer.decide_fate_cb = just_die;

	table->drop_v4_syn = DEFAULT_DROP_EXTERNAL_CONNECTIONS;
	table->drop_by_addr = DEFAULT_ADDR_DEPENDENT_FILTERING;
	table->log_bibs = DEFAULT_BIB_LOGGING;
	table->log_sessions = DEFAULT_SESSION_LOGGING;
	spin_lock_init(&table->lock);
}

/* TODO (final) maybe put this in some common header? */
enum session_fate tcp_expired_cb(struct session_entry *session, void *arg);

struct bib *bib_create(void)
{
	struct bib *db;

	db = wkmalloc(struct bib, GFP_KERNEL);
	if (!db)
		return NULL;

	init_table(&db->udp, UDP_DEFAULT, 0, just_die);
	init_table(&db->tcp, TCP_EST, TCP_TRANS, tcp_expired_cb);
	init_table(&db->icmp, ICMP_DEFAULT, 0, just_die);

	/** Packet storage for simultaneous open of TCP connections. */
	db->pkt_queue = pktqueue_create();
	if (!db->pkt_queue) {
		wkfree(struct bib, db);
		return NULL;
	}

	kref_init(&db->refs);

	return db;
}

void bib_get(struct bib *db)
{
	kref_get(&db->refs);
}

static void release_session(struct rb_node *node, void *arg)
{
	struct tabled_session *session = node2session(node);
	rbtree_clear(&session->subtree, release_session, NULL);
	kmem_cache_free(session_cache, session);
}

static void release_bib_entry(struct rb_node *node, void *arg)
{
	struct tabled_bib *bib = bib6_entry(node);
	rbtree_clear(&bib->sessions, release_session, NULL);
	kmem_cache_free(bib_cache, bib);
}

static void release_bib(struct kref *refs)
{
	struct bib *db;
	db = container_of(refs, struct bib, refs);

	/**
	 * The trees share the entries, so only one tree of each protocol
	 * needs to be emptied.
	 */
	rbtree_clear(&db->udp.tree6, release_bib_entry, NULL);
	rbtree_clear(&db->tcp.tree6, release_bib_entry, NULL);
	rbtree_clear(&db->icmp.tree6, release_bib_entry, NULL);
	pktqueue_destroy(db->pkt_queue);

	wkfree(struct bib, db);
}

void bib_put(struct bib *db)
{
	kref_put(&db->refs, release_bib);
}

void bib_config_copy(struct bib *db, struct bib_config *config)
{
	spin_lock_bh(&db->tcp.lock);
	config->ttl.tcp_est = db->tcp.est_timer.timeout;
	config->ttl.tcp_trans = db->tcp.trans_timer.timeout;
	config->bib_logging = db->tcp.log_bibs;
	config->session_logging = db->tcp.log_sessions;
	pktqueue_config_copy(db->pkt_queue, &config->pktqueue);
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
	db->tcp.est_timer.timeout = config->ttl.tcp_est;
	db->tcp.trans_timer.timeout = config->ttl.tcp_trans;
	db->tcp.log_bibs = config->bib_logging;
	db->tcp.log_sessions = config->session_logging;
	pktqueue_config_set(db->pkt_queue, &config->pktqueue);
	spin_unlock_bh(&db->tcp.lock);

	spin_lock_bh(&db->udp.lock);
	db->udp.est_timer.timeout = config->ttl.udp;
	spin_unlock_bh(&db->udp.lock);

	spin_lock_bh(&db->icmp.lock);
	db->icmp.est_timer.timeout = config->ttl.icmp;
	spin_unlock_bh(&db->icmp.lock);
}

static void log_bib(struct bib_table *table, struct tabled_bib *bib,
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

static void log_session(struct bib_table *table, struct tabled_session *session,
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

static int compare_dst4l3(struct tabled_session *s1, struct tabled_session *s2)
{
	return ipv4_addr_cmp(&s1->dst4.l3, &s2->dst4.l3);
}

static struct rb_root *find_sessions_root(struct tabled_session *session)
{
	struct tabled_session *found;

	found = rbtree_find(session, &session->bib->sessions,
			compare_dst4l3, struct tabled_session, tree_hook);
	if (unlikely(!found))
		return NULL;

	return (session->dst4.l4 == found->dst4.l4)
			? &session->bib->sessions
			: &found->subtree;
}

/**
 * Removes all of this database's references towards "session", and drops its
 * refcount accordingly.
 *
 * "table"'s spinlock must already be held.
 */
static void rm(struct bib_table *table, struct tabled_session *session)
{
	struct tabled_bib *bib;
	struct rb_node *replacement;
	struct rb_root *root;

	/*
	 * Remove the session from the data structures; tree first.
	 *
	 * This is not just a rb_erase for two reasons:
	 * a) The session might belong to a subtree, not the BIB entry's tree.
	 * b) The session might have a subtree, which must survive.
	 */
	root = find_sessions_root(session);
	if (WARN(!root, "Critical: Session's IPv4 tree has no root.")) {
		/*
		 * The database is inconsistent; Jool is going to crash the
		 * kernel soon. But do not BUG_ON() still since our leaving the
		 * WARN early here can lead to the error message more likely end
		 * up in persistent storage, which makes it easier to find.
		 */
		return;
	}
	if (RB_EMPTY_ROOT(&session->subtree)) {
		rb_erase(&session->tree_hook, root);
	} else {
		/* Any node in the subtree is a fine replacement. */
		replacement = session->subtree.rb_node;
		rb_erase(replacement, &session->subtree);
		rb_replace_node(&session->tree_hook, replacement, root);
		node2session(replacement)->subtree = session->subtree;
	}

	list_del(&session->list_hook);

	/* Post-removal paperwork. */
	log_session(table, session, "Forgot session");
	kmem_cache_free(session_cache, session);
	table->session_count--;

	/* Cascade removal to the BIB entry, if applies. */
	bib = session->bib;
	if (!bib->is_static && RB_EMPTY_ROOT(&bib->sessions)) {
		rb_erase(&bib->hook6, &table->tree6);
		rb_erase(&bib->hook4, &table->tree4);
		log_bib(table, bib, "Forgot");
		kmem_cache_free(bib_cache, bib);
		table->bib_count--;
	}
}

static void queue_unsorted_session(struct expire_timer *timer,
		struct tabled_session *new)
{
	struct list_head *list;
	struct list_head *cursor;
	struct tabled_session *old;

	new->expirer = timer;
	list_del(&new->list_hook);

	list = &timer->sessions;
	for (cursor = list->prev; cursor != list; cursor = cursor->prev) {
		old = list_entry(cursor, struct tabled_session, list_hook);
		if (old->update_time < new->update_time) {
			list_add(&new->list_hook, &old->list_hook);
			return;
		}
	}

	list_add(&new->list_hook, list);
}

static void handle_fate_timer_est(struct bib_table *table,
		struct tabled_session *session)
{
	session->update_time = jiffies;
	session->expirer = &table->est_timer;
	list_del(&session->list_hook);
	list_add_tail(&session->list_hook, &session->expirer->sessions);
}

/**
 * Assumes result->session has been set (result->session_set is true).
 */
static void decide_fate(struct collision_cb *cb,
		struct bib_table *table,
		struct tabled_session *session,
		struct list_head *probes)
{
	struct session_entry tmp;
	struct probing_session *probe;
	enum session_fate fate;

	if (!cb)
		return;

	tstose(session, &tmp);
	fate = cb->cb(&tmp, cb->arg);
	session->state = tmp.state;

	switch (fate) {
	case FATE_TIMER_EST:
		handle_fate_timer_est(table, session);
		break;
	case FATE_PROBE:
		if (WARN(!probes, "Probe needed but caller doesn't support it"))
			return;

		/*
		 * Why add a dummy session instead of the real one?
		 * Because the real session's list hook must remain
		 * attached to the database.
		 */
		probe = wkmalloc(struct probing_session, GFP_ATOMIC);
		if (probe) {
			probe->session = tmp;
			list_add(&probe->list_hook, probes);
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
	struct probing_session *probe;
	struct probing_session *tmp;

	list_for_each_entry_safe(probe, tmp, probes, list_hook) {
		send_probe_packet(ns, &probe->session);
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
	/*
	 * Please do not override session->update_time here;
	 * joold needs to define update time on its own.
	 */
	list_add_tail(&session->list_hook, &expirer->sessions);
	session->expirer = expirer;
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

static int compare_src6_rbnode(struct rb_node *a, struct rb_node *b)
{
	return taddr6_compare(&bib6_entry(a)->src6, &bib6_entry(b)->src6);
}

static int compare_src6(struct tabled_bib *a, struct ipv6_transport_addr *b)
{
	return taddr6_compare(&a->src6, b);
}

static struct tabled_bib *find_bibtree6_slot(struct bib_table *table,
		struct tabled_bib *new,
		struct tree_slot *slot)
{
	struct rb_node *collision;
	collision = rbtree_find_slot(&new->hook6, &table->tree6,
			compare_src6_rbnode, slot);
	return collision ? bib6_entry(collision) : NULL;
}

static struct tabled_bib *find_bibtree4_slot(struct bib_table *table,
		struct tabled_bib *new,
		struct tree_slot *slot)
{
	struct rb_node *collision;
	collision = rbtree_find_slot(&new->hook4, &table->tree4,
			compare_src4_rbnode, slot);
	return collision ? bib4_entry(collision) : NULL;
}

static int create_bib_session6(struct bib_session_tuple *tuple,
		struct tuple *tuple6, struct ipv4_transport_addr *dst4,
		tcp_state state)
{
	tuple->bib = kmem_cache_alloc(bib_cache, GFP_ATOMIC);
	if (!tuple->bib)
		return -ENOMEM;
	tuple->session = kmem_cache_alloc(session_cache, GFP_ATOMIC);
	if (!tuple->session) {
		kmem_cache_free(bib_cache, tuple->bib);
		return -ENOMEM;
	}

	tuple->bib->src6 = tuple6->src.addr6;
	tuple->bib->proto = tuple6->l4_proto;
	tuple->bib->is_static = false;
	tuple->bib->sessions = RB_ROOT;
	tuple->session->dst6 = tuple6->dst.addr6;
	tuple->session->dst4 = *dst4;
	tuple->session->state = state;
	return 0;
}

static struct tabled_session *create_session4(struct tuple *tuple4,
		struct ipv6_transport_addr *dst6, tcp_state state)
{
	struct tabled_session *session;

	session = kmem_cache_alloc(session_cache, GFP_ATOMIC);
	if (!session)
		return NULL;

	session->dst6 = *dst6;
	session->dst4 = tuple4->src.addr4;
	session->state = state;

	return session;
}

static int compare_dst4l3_rbnode(struct rb_node *a, struct rb_node *b)
{
	return ipv4_addr_cmp(&node2session(a)->dst4.l3,
			&node2session(b)->dst4.l3);
}

static int compare_dst4l4_rbnode(struct rb_node *a, struct rb_node *b)
{
	return ((int)node2session(a)->dst4.l4)
			- ((int)node2session(b)->dst4.l4);
}

static struct tabled_session *find_session_slot(struct tabled_bib *bib,
		struct tabled_session *session,
		bool *allow,
		struct tree_slot *slot)
{
	struct rb_node *collision;

	if (!bib)
		return NULL;

	collision = rbtree_find_slot(&session->tree_hook, &bib->sessions,
			compare_dst4l3_rbnode, slot);
	if (!collision) {
		*allow = false;
		return NULL;
	}

	*allow = true;

	collision = rbtree_find_slot(&session->tree_hook,
			&node2session(collision)->subtree,
			compare_dst4l4_rbnode, slot);
	return collision ? node2session(collision) : NULL;
}

static struct tabled_bib *try_next(struct bib_table *table,
		struct tabled_bib *collision,
		struct tabled_bib *bib,
		struct tree_slot *slot)
{
	struct tabled_bib *next;

	next = bib4_entry(rb_next(&collision->hook4));

	if (taddr4_equals(&next->src4, &bib->src4))
		return next; /* Next is yet another collision. */

	slot->tree = &table->tree4;
	slot->entry = &next->hook4;
	if (collision->hook4.rb_right) {
		slot->parent = &next->hook4;
		slot->rb_link = &slot->parent->rb_left;
	} else {
		slot->parent = &collision->hook4;
		slot->rb_link = &slot->parent->rb_right;
	}
	return NULL;
}

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
		collision = consecutive
				? try_next(table, collision, bib, slot)
				: find_bibtree4_slot(table, bib, slot);
	} while (collision);

	return 0;
}

static int find_bib_session6(struct bib_table *table,
		struct mask_domain *masks,
		struct bib_session_tuple *new,
		struct bib_session_tuple *old,
		struct slot_group *slots)
{
	int error;

	old->bib = find_bibtree6_slot(table, new->bib, &slots->bib6);
	if (old->bib) {
		old->session = find_session_slot(old->bib, new->session, NULL,
				&slots->session);
		return 0;
	}

	error = find_available_mask(table, masks, new->bib, &slots->bib4);
	if (error)
		return error;

	treeslot_init(&slots->session, &new->bib->sessions,
			&new->session->tree_hook);
	old->session = NULL;

	return 0;
}

/**
 * @db current BIB & session database.
 * @masks IPv4 transport addresses that can be used to mask the connection.
 *     One (available) from here will be chosen and assigned to @tuple6.
 * @tuple6 The connection that you want to mask.
 * @state Should a session be created, this is the state it will begin in.
 * @est Should a session be created, this is the timer that will expire it.
 *     Established is true, transitory is false.
 * @result The resulting session will be placed here. (if not NULL.)
 */
int bib_add6(struct bib *db, struct mask_domain *masks, struct tuple *tuple6,
		struct ipv4_transport_addr *dst4, struct bib_session *result)
{
	struct bib_table *table;
	struct bib_session_tuple new;
	struct bib_session_tuple old;
	struct slot_group slots;
	int error;

	table = get_table(db, tuple6->l4_proto);
	if (!table)
		return -EINVAL;

	/*
	 * We might have a lot to do. This function may index four RB-trees
	 * so spinlock time is tight.
	 *
	 * (That's 4 potential lookups (2 guaranteed) and 3 potential
	 * rebalances, though at least one of the trees is usually minuscule.)
	 *
	 * Let's start by allocating and initializing the objects as much as we
	 * can, even if we end up not needing them.
	 */

	error = create_bib_session6(&new, tuple6, dst4, ESTABLISHED);
	if (error)
		return error;

	spin_lock_bh(&table->lock); /* Here goes... */

	error = find_bib_session6(table, masks, &new, &old, &slots);
	if (error)
		goto end;

	if (old.session) {
		handle_fate_timer_est(table, old.session);
		tstobs(old.session, result);
		goto end;
	}

	new.session->bib = old.bib ? : new.bib;
	commit_session_add(table, &slots.session);
	attach_timer(new.session, &table->est_timer);
	log_new_session(table, new.session);
	tstobs(new.session, result);
	new.session = NULL; /* Do not free! */

	if (!old.bib) {
		commit_bib_add(table, &slots);
		log_new_bib(table, new.bib);
		new.bib = NULL; /* Do not free! */
	}

	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new.bib)
		kmem_cache_free(bib_cache, new.bib);
	if (new.session)
		kmem_cache_free(session_cache, new.session);

	return error;
}

static struct tabled_bib *find_bib4(struct bib_table *table,
		struct ipv4_transport_addr *addr)
{
	return rbtree_find(addr, &table->tree4, compare_src4, struct tabled_bib,
			hook4);
}

static void find_bib_session4(struct bib_table *table,
		struct tuple *tuple4,
		struct tabled_session *new,
		struct bib_session_tuple *old,
		bool *allow,
		struct tree_slot *slot)
{
	old->bib = find_bib4(table, &tuple4->dst.addr4);
	old->session = find_session_slot(old->bib, new, allow, slot);
}

/**
 * See @bib_add6.
 */
int bib_add4(struct bib *db, struct ipv6_transport_addr *dst6,
		struct tuple *tuple4, struct bib_session *result)
{
	struct bib_table *table;
	struct bib_session_tuple old;
	struct tabled_session *new;
	struct tree_slot session_slot;
	bool allow;
	int error;

	table = get_table(db, tuple4->l4_proto);
	if (!table)
		return -EINVAL;

	new = create_session4(tuple4, dst6, ESTABLISHED);
	if (!new)
		return -ENOMEM;

	spin_lock_bh(&table->lock);

	find_bib_session4(table, tuple4, new, &old, &allow, &session_slot);

	if (old.session) {
		handle_fate_timer_est(table, old.session);
		tstobs(old.session, result);
		goto success;
	}

	if (old.bib) {
		if (table->drop_by_addr && !allow) {
			error = -EPERM;
			goto failure;
		}

		new->bib = old.bib;
		commit_session_add(table, &session_slot);
		attach_timer(new, &table->trans_timer);
		log_new_session(table, new);
		tstobs(new, result);
		new = NULL;
		goto success;
	}

	error = -ESRCH;
	/* Fall through */

failure:
	spin_unlock_bh(&table->lock);
	kmem_cache_free(session_cache, new);
	return error;

success:
	attach_timer(new, &table->est_timer);
	table->session_count++;

	spin_unlock_bh(&table->lock);

	return 0;
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
	verdict verdict = VERDICT_CONTINUE;

	table = get_table(db, pkt->tuple.l4_proto);
	if (!table)
		return VERDICT_DROP;

	if (create_bib_session6(&new, &pkt->tuple, dst4, V6_INIT))
		return VERDICT_DROP;

	spin_lock_bh(&table->lock);

	if (find_bib_session6(table, masks, &new, &old, &slots)) {
		verdict = VERDICT_DROP;
		goto end;
	}

	if (old.session) {
		/* All states except CLOSED. */
		decide_fate(cb, table, old.session, NULL);
		tstobs(old.session, result);
		goto end;
	}

	/* CLOSED state beginning now. */

	if (!pkt_tcp_hdr(pkt)->syn) {
		if (old.bib)
			tbtobs(old.bib, result);
		else
			verdict = VERDICT_DROP;
		goto end;
	}

	/* All exits up till now require @new.* to be deleted. */

	new.session->bib = old.bib ? : new.bib;
	commit_session_add(table, &slots.session);
	attach_timer(new.session, &table->trans_timer);
	log_new_session(table, new.session);
	tstobs(new.session, result);
	new.session = NULL;

	if (!old.bib) {
		commit_bib_add(table, &slots);
		log_new_bib(table, new.bib);
		new.bib = NULL;
	}

	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new.bib)
		kmem_cache_free(bib_cache, new.bib);
	if (new.session)
		kmem_cache_free(session_cache, new.session);

	return verdict;
}

static verdict store_pkt(struct bib *db,
		struct packet *pkt,
		struct tabled_bib *tbib,
		struct ipv6_transport_addr *dst6)
{
	struct pktqueue_session session;

	if (tbib) {
		session.src6 = tbib->src6;
		session.src6_set = true;
	} else {
		memset(&session.src6, 0, sizeof(session.src6));
		session.src6_set = false;
	}
	session.dst6 = *dst6;
	session.src4 = pkt->tuple.dst.addr4;
	session.dst4 = pkt->tuple.src.addr4;

	return pktqueue_add(db->pkt_queue, &session, pkt)
			? VERDICT_DROP
			: VERDICT_STOLEN;
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
	verdict verdict = VERDICT_CONTINUE;

	table = get_table(db, pkt->tuple.l4_proto);
	if (!table)
		return VERDICT_DROP;

	new = create_session4(&pkt->tuple, dst6, V4_INIT);
	if (!new)
		return VERDICT_DROP;

	spin_lock_bh(&table->lock);

	find_bib_session4(table, &pkt->tuple, new, &old, NULL, &session_slot);

	if (old.session) {
		/* All states except CLOSED. */
		decide_fate(cb, table, old.session, NULL);
		tstobs(old.session, result);
		goto end;
	}

	/* CLOSED state beginning now. */

	if (!pkt_tcp_hdr(pkt)->syn) {
		if (old.bib)
			tbtobs(old.bib, result);
		else
			verdict = VERDICT_DROP;
		goto end;
	}

	if (table->drop_v4_syn) {
		verdict = VERDICT_DROP;
		goto end;
	}

	if (old.bib) {
		if (table->drop_by_addr) {
			verdict = store_pkt(db, pkt, old.bib, dst6);
		} else {
			new->bib = old.bib;
			commit_session_add(table, &session_slot);
			attach_timer(new, &table->trans_timer);
			log_new_session(table, new);
			tstobs(new, result);
			new = NULL;
		}
	} else {
		verdict = store_pkt(db, pkt, old.bib, dst6);
	}
	/* Fall through */

end:
	spin_unlock_bh(&table->lock);

	if (new)
		kmem_cache_free(session_cache, new);

	return verdict;
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

int bib_add_session(struct bib *db, struct session_entry *session,
		struct collision_cb *cb)
{
	log_err("Not implemented yet");
	return -EINVAL;

	// The code below needs a few adjustments (the compiler will point them
	// out) but I want to test the stuff above before investing too much
	// time in this.

	/*
	struct bib_table *table;
	struct bib_session_tuple new;
	struct bib_session_tuple old;
	struct slot_group slots;
	int error;

	table = get_table(db, session->proto);
	if (!table)
		return -EINVAL;

	error = create_bib_session6(&new, tuple6, masks, ESTABLISHED);
	if (error)
		return error;

	spin_lock_bh(&table->lock);

	error = find_bib_session6(table, masks, &new, &old, &slots);
	if (error)
		goto end;

	if (old.session) {
		decide_fate(cb, table, &old, NULL);
		goto end;
	}

	commit_session_add(table, &slots.session);
	attach_timer(new.session, session->established
			? &table->est_timer
			: &table->trans_timer);
	log_new_session(table, new.session);
	new.session = NULL; // Do not free!

	if (!old.bib) {
		commit_bib_add(table, &slots);
		log_new_bib(table, new.bib);
		new.bib = NULL; // Do not free!
	}

	// Fall through

end:
	spin_unlock_bh(&table->lock);

	if (new.bib)
		kmem_cache_free(bib_cache, new.bib);
	if (new.session)
		kmem_cache_free(session_cache, new.session);

	return error;
	*/
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

	spin_lock_bh(&table->lock);
	__clean(&table->est_timer, table, &probes);
	__clean(&table->trans_timer, table, &probes);
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
//	pktqueue_clean(db->pkt_queue);
}

static struct rb_node *find_starting_point(struct bib_table *table,
		const struct ipv4_transport_addr *offset, bool include_offset)
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

int bib_foreach_session(struct bib *db, l4_protocol proto,
		struct session_foreach_func *collision_cb,
		struct session_foreach_offset *offset)
{
	log_err("Not implemented yet."); /* TODO */
	return -EINVAL;
}

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
	bib = rbtree_find(addr, &table->tree6, compare_src6, struct tabled_bib,
			hook6);
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
	bib = rbtree_find(addr, &table->tree4, compare_src4, struct tabled_bib,
			hook4);
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

	bib = kmem_cache_alloc(bib_cache, GFP_ATOMIC);
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

	spin_unlock_bh(&table->lock);
	return 0;

upgrade:
	collision->is_static = true;
	spin_unlock_bh(&table->lock);
	kmem_cache_free(bib_cache, bib);
	return 0;

eexist:
	tbtobe(collision, old);
	spin_unlock_bh(&table->lock);
	kmem_cache_free(bib_cache, bib);
	return -EEXIST;
}

#define tree_foreach rbtree_postorder_for_each_entry_safe /* Geez wtf man */

static unsigned int detach_sessions(struct tabled_bib *bib)
{
	struct tabled_session *session, *tmp;
	struct tabled_session *session2, *tmp2;
	unsigned int detached = 0;

	tree_foreach(session, tmp, &bib->sessions, tree_hook) {
		tree_foreach(session2, tmp2, &session->subtree, tree_hook) {
			list_del(&session2->list_hook);
			detached++;
		}
		list_del(&session->list_hook);
		detached++;
	}

	return detached;
}

static void detach_bib(struct bib_table *table, struct tabled_bib *bib)
{
	rb_erase(&bib->hook6, &table->tree6);
	rb_erase(&bib->hook4, &table->tree4);
	table->bib_count--;
	table->session_count -= detach_sessions(bib);
}

static void destroy_bib(struct tabled_bib *bib)
{
	struct tabled_session *session, *tmp;
	struct tabled_session *session2, *tmp2;

	/*
	 * kmem_cache_free() is kind of bulky inside; that's the reason
	 * why I bother with this mess after the spinlock.
	 */
	tree_foreach(session, tmp, &bib->sessions, tree_hook) {
		tree_foreach(session2, tmp2, &session->subtree, tree_hook)
			kmem_cache_free(session_cache, session2);
		kmem_cache_free(session_cache, session);
	}
	kmem_cache_free(bib_cache, bib);
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

	bib = rbtree_find(&key.src6, &table->tree6, compare_src6,
			struct tabled_bib, hook6);
	if (bib && taddr4_equals(&key.src4, &bib->src4)) {
		detach_bib(table, bib);
		error = 0;
	}

	spin_unlock_bh(&table->lock);

	if (!error)
		destroy_bib(bib);

	return error;
}

struct bib_delete_list {
	struct rb_node *first;
	struct rb_node *last;
};

static void delete_list_add(struct bib_delete_list *list, struct rb_node *node)
{
	if (list->first)
		list->last->rb_right = node;
	else
		list->first = node;
	list->last = node;
	list->last->rb_right = NULL;
}

static void delete_list_commit(struct bib_delete_list *list)
{
	struct rb_node *node;
	struct rb_node *next;

	for (node = list->first; node; node = next) {
		next = node->rb_right;
		destroy_bib(bib4_entry(node));
	}
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
			delete_list_add(&delete_list, node);
		}
	}

	spin_unlock_bh(&table->lock);

	delete_list_commit(&delete_list);
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
		delete_list_add(&delete_list, node);
	}

	spin_unlock_bh(&table->lock);

	delete_list_commit(&delete_list);
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
