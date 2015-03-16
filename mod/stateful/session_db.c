#include "nat64/mod/stateful/session_db.h"

#include <net/ipv6.h>
#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/rfc6052.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/stateful/bib_db.h"
#include "nat64/mod/stateful/pkt_queue.h"

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

/**
 * A timer which will delete expired sessions every once in a while.
 * All of the timer's sessions have the same time to live.
 *
 * Why not a single timer which takes care of all the sessions? Some reasons I remember:
 * - When the user updates timeouts, this makes updating existing sessions a O(1) operation (since
 *   the timer holds the timeout, not the sessions).
 * - It makes timer rescheduling trivial (sessions are sorted by expiration date, so new sessions
 *   are always simply added to the end of the list (O(1)) and knowing when the timer should be
 *   triggered next is a matter of peeking the first element (also O(1)).
 * - I seem to recall it takes care of some sync concern, but I can't remember what it was.
 *
 * Why not a timer per session? Well I don't know, it sounds like a lot of stress to the kernel
 * since we expect lots and lots of sessions.
 */
struct expire_timer {
	/** The actual timer. */
	struct timer_list timer;
	/** The sessions this timer is supposed to delete. Sorted by expiration time. */
	struct list_head sessions;
	/** All the sessions from the list above belong to this table (the reverse might not apply). */
	struct session_table *table;

	unsigned long (*get_timeout)(void);
	char *name;
};

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

static char* EXPIRER_NAMES[] = { "UDP", "ICMP", "TCP_EST", "TCP_TRANS", "TCP_SYN" };

/** Cache for struct session_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

static void session_release(struct kref *ref)
{
	struct session_entry *session;
	session = container_of(ref, struct session_entry, refcounter);

	if (session->bib)
		bib_return(session->bib);
	kmem_cache_free(entry_cache, session);
}

static int session_init(void)
{
	entry_cache = kmem_cache_create("jool_session_entries", sizeof(struct session_entry),
			0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the Session entry cache.");
		return -ENOMEM;
	}

	return 0;
}

static void session_destroy(void)
{
	kmem_cache_destroy(entry_cache);
}

int session_return(struct session_entry *session)
{
	return kref_put(&session->refcounter, session_release);
}

void session_get(struct session_entry *session)
{
	kref_get(&session->refcounter);
}

/**
 * Creates a copy of "session".
 *
 * The copy will not be part of the database regardless of session's state.
 */
static struct session_entry *session_clone(struct session_entry *session)
{
	struct session_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	memcpy(result, session, sizeof(*session));
	kref_init(&result->refcounter);
	INIT_LIST_HEAD(&result->expire_list_hook);
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);

	if (session->bib)
		bib_get(session->bib);

	return result;
}

struct session_entry *session_create(const struct ipv6_transport_addr *remote6,
		const struct ipv6_transport_addr *local6,
		const struct ipv4_transport_addr *local4,
		const struct ipv4_transport_addr *remote4,
		l4_protocol l4_proto, struct bib_entry *bib)
{
	struct session_entry tmp = {
			.remote6 = *remote6,
			.local6 = *local6,
			.local4 = *local4,
			.remote4 = *remote4,
			.update_time = jiffies,
			.bib = bib,
			.l4_proto = l4_proto,
			.state = 0,
			.expirer = NULL,
	};
	return session_clone(&tmp);
}

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
	case L4PROTO_OTHER:
		break;
	}

	WARN(true, "Unsupported transport protocol: %u.", l4_proto);
	return -EINVAL;
}

static int compare_addr6(const struct ipv6_transport_addr *a1, const struct ipv6_transport_addr *a2)
{
	int gap;

	gap = ipv6_addr_cmp(&a1->l3, &a2->l3);
	if (gap)
		return gap;

	gap = a1->l4 - a2->l4;
	return gap;
}

static int compare_session6(const struct session_entry *s1, const struct session_entry *s2)
{
	int gap;

	gap = compare_addr6(&s1->local6, &s2->local6);
	if (gap)
		return gap;

	gap = compare_addr6(&s1->remote6, &s2->remote6);
	return gap;
}

/**
 * Returns > 0 if session.*6 > tuple6.*.addr6.
 * Returns < 0 integer if session.*6 < tuple6.*.addr6.
 * Returns 0 if session.*6 == tuple6.*.addr6.
 *
 * Doesn't care about spinlocks.
 */
static int compare_full6(const struct session_entry *session, const struct tuple *tuple6)
{
	int gap;

	gap = compare_addr6(&session->local6, &tuple6->dst.addr6);
	if (gap)
		return gap;

	gap = compare_addr6(&session->remote6, &tuple6->src.addr6);
	return gap;
}

static int compare_addr4(const struct ipv4_transport_addr *a1, const struct ipv4_transport_addr *a2)
{
	int gap;

	gap = ipv4_addr_cmp(&a1->l3, &a2->l3);
	if (gap)
		return gap;

	gap = a1->l4 - a2->l4;
	return gap;
}

static int compare_session4(const struct session_entry *s1, const struct session_entry *s2)
{
	int gap;

	gap = compare_addr4(&s1->remote4, &s2->remote4);
	if (gap)
		return gap;

	gap = compare_addr4(&s1->local4, &s2->local4);
	return gap;
}

/**
 * Returns > 0 if session.local4 > addr.
 * Returns < 0 if session.local4 < addr.
 * Returns 0 if session.local4 == addr.
 *
 * Doesn't care about spinlocks.
 */
static int compare_local4(const struct session_entry *session,
		const struct ipv4_transport_addr *addr)
{
	return compare_addr4(&session->local4, addr);
}

/**
 * Returns > 0 if session.*4 > tuple4.*.addr4.
 * Returns < 0 if session.*4 < tuple4.*.addr4.
 * Returns 0 if session.*4 == tuple4.*.addr4.
 *
 * It excludes remote layer-4 IDs from the comparison. See sessiondb_allow() to find out why.
 *
 * Doesn't care about spinlocks.
 */
static int compare_addrs4(const struct session_entry *session, const struct tuple *tuple4)
{
	int gap;

	gap = compare_addr4(&session->local4, &tuple4->dst.addr4);
	if (gap)
		return gap;

	gap = ipv4_addr_cmp(&session->remote4.l3, &tuple4->src.addr4.l3);
	return gap;
}

/**
 * Returns > 0 if session.*4 > tuple4.*.addr4.
 * Returns < 0 if session.*4 < tuple4.*.addr4.
 * Returns 0 if session.*4 == tuple4.*.addr4.
 *
 * Doesn't care about spinlocks.
 */
static int compare_full4(const struct session_entry *session, const struct tuple *tuple4)
{
	int gap;

	gap = compare_addr4(&session->remote4, &tuple4->src.addr4);
	if (gap)
		return gap;

	gap = compare_addr4(&session->local4, &tuple4->dst.addr4);
	return gap;
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
	iph->saddr = session->local6.l3;
	iph->daddr = session->remote6.l3;

	th = tcp_hdr(skb);
	th->source = cpu_to_be16(session->local6.l4);
	th->dest = cpu_to_be16(session->remote6.l4);
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

	pkt_fill(&pkt, skb, L3PROTO_IPV6, L4PROTO_TCP, NULL, th + 1, NULL);

	error = route6(&pkt);
	if (error)
		goto fail;

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

int sessiondb_get_timeout(struct session_entry *session, unsigned long *result)
{
	if (!session->expirer) {
		log_debug("The session entry doesn't have an expirer");
		return -EINVAL;
	}

	*result = session->expirer->get_timeout();
	return 0;
}

/**
 * Helper of the set_*_timer functions. Safely updates "session"->dying_time using "ttl" and moves
 * it from its original location to the end of "list".
 */
static struct expire_timer *set_timer(struct session_entry *session,
		struct expire_timer *expirer)
{
	struct expire_timer *result;

	session->update_time = jiffies;
	list_del(&session->expire_list_hook);
	list_add_tail(&session->expire_list_hook, &expirer->sessions);
	session->expirer = expirer;

	/*
	 * The new session is always going to expire last.
	 * So if the timer is already set, there should be no reason to edit it.
	 */
	result = timer_pending(&expirer->timer) ? NULL : expirer;

	return result;
}

static void commit_timer(struct expire_timer *expirer)
{
	if (expirer)
		schedule_timer(&expirer->timer, jiffies + expirer->get_timeout(), expirer->name);
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

	timeout = expirer->get_timeout();
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

	if (schedule_tcp_trans) {
		schedule_timer(&expirer_tcp_trans.timer, jiffies + expirer_tcp_trans.get_timeout(),
				expirer_tcp_trans.name);
	}

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

static unsigned long get_syn_timeout(void)
{
	return msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
}

/**
 * Auxiliar for sessiondb_init(). Encapsulates initialization of an expire_timer structure.
 *
 * Doesn't care about spinlocks (initialization code doesn't share threads).
 */
static void init_expire_timer(struct expire_timer *expirer, struct session_table *table,
		unsigned long (*get_timeout)(void), char *expirer_name)
{
	init_timer(&expirer->timer);
	expirer->timer.function = cleaner_timer;
	expirer->timer.expires = 0;
	expirer->timer.data = (unsigned long) expirer;

	INIT_LIST_HEAD(&expirer->sessions);
	expirer->table = table;
	expirer->get_timeout = get_timeout;
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

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		tables[i]->tree6 = RB_ROOT;
		tables[i]->tree4 = RB_ROOT;
		tables[i]->count = 0;
		spin_lock_init(&tables[i]->lock);
	}

	init_expire_timer(&expirer_udp, &session_table_udp, config_get_ttl_udp, EXPIRER_NAMES[0]);
	init_expire_timer(&expirer_icmp, &session_table_icmp, config_get_ttl_icmp, EXPIRER_NAMES[1]);
	init_expire_timer(&expirer_tcp_est, &session_table_tcp, config_get_ttl_tcpest,
			EXPIRER_NAMES[2]);
	init_expire_timer(&expirer_tcp_trans, &session_table_tcp, config_get_ttl_tcptrans,
			EXPIRER_NAMES[3]);
	init_expire_timer(&expirer_syn, &session_table_tcp, get_syn_timeout, EXPIRER_NAMES[4]);

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

static struct session_entry *get_by_ipv6(struct session_table *table, struct tuple *tuple)
{
	return rbtree_find(tuple, &table->tree6, compare_full6, struct session_entry, tree6_hook);
}

static struct session_entry *get_by_ipv4(struct session_table *table, struct tuple *tuple)
{
	return rbtree_find(tuple, &table->tree4, compare_full4, struct session_entry, tree4_hook);
}

int sessiondb_get(struct tuple *tuple, struct session_entry **result)
{
	struct in6_addr any = IN6ADDR_ANY_INIT;
	struct session_table *table;
	struct session_entry *session;
	int error;

	if (WARN(!tuple, "There's no session entry mapped to NULL."))
		return -EINVAL;

	error = get_session_table(tuple->l4_proto, &table);
	if (error)
		return error;

	spin_lock_bh(&table->lock);
	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		session = get_by_ipv6(table, tuple);
		break;
	case L3PROTO_IPV4:
		session = get_by_ipv4(table, tuple);
		break;
	default:
		WARN(true, "Unsupported network protocol: %u.", tuple->l3_proto);
		spin_unlock_bh(&table->lock);
		return -EINVAL;
	}

	if (session)
		session_get(session);

	spin_unlock_bh(&table->lock);

	if (!session)
		return -ENOENT;

	if (addr6_equals(&session->remote6.l3, &any)) {
		/* The session is Simultaneous Open debris. */
		session_return(session);
		return -ENOENT;
	}

	*result = session;
	return 0;
}

bool sessiondb_allow(struct tuple *tuple4)
{
	struct session_table *table;
	struct session_entry *session;
	int error;
	bool result;

	/* Sanity */
	if (WARN(!tuple4, "Cannot extract addresses from NULL."))
		return false;
	error = get_session_table(tuple4->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	spin_lock_bh(&table->lock);
	session = rbtree_find(tuple4, &table->tree4, compare_addrs4, struct session_entry, tree4_hook);
	result = session ? true : false;
	spin_unlock_bh(&table->lock);

	return result;
}

static bool is_set(const struct ipv6_transport_addr *addr)
{
	return addr->l3.s6_addr32[0]
			|| addr->l3.s6_addr32[1]
			|| addr->l3.s6_addr32[2]
			|| addr->l3.s6_addr32[3]
			|| addr->l4;
}

int sessiondb_add(struct session_entry *session, enum session_timer_type timer_type)
{
	struct session_table *table;
	struct rb_node *parent, **node;
	struct expire_timer *expirer = NULL;
	int error;

	/* Sanity */
	if (WARN(!session, "Cannot insert NULL to a session table."))
		return -EINVAL;
	error = get_session_table(session->l4_proto, &table);
	if (error)
		return error;

	/* Action */
	spin_lock_bh(&table->lock);

	error = rbtree_add(session, session, &table->tree6, compare_session6, struct session_entry,
			tree6_hook);
	if (error) {
		spin_unlock_bh(&table->lock);
		return -EEXIST;
	}

	rbtree_find_node(session, &table->tree4, compare_session4, struct session_entry,
			tree4_hook, parent, node);
	if (*node) {
		/*
		 * This can happen on Simultaneous Open (SO) of TCP connections.
		 * An incomplete dummy session was inserted to the database (we didn't have the remote
		 * IPv6 address at the time), and now we have to replace it with the full version.
		 */
		struct session_entry *other;
		other = rb_entry(*node, struct session_entry, tree4_hook);

		if (WARN(is_set(&other->remote6), "IPv6 index worked, IPv4 index didn't."))
			goto index_trainwreck; /* No actually a SO; this should never happen. */

		pktqueue_remove(other); /* Not sure what to make out it if this fails. */

		table->count -= remove(other, table);
		error = rbtree_add(session, session, &table->tree4, compare_session4, struct session_entry,
				tree4_hook);
		if (WARN(error, "Just removed the conflicting session, insertion still failed."))
			goto index_trainwreck;

	} else {
		rb_link_node(&session->tree4_hook, parent, node);
		rb_insert_color(&session->tree4_hook, &table->tree4);
	}

	switch (timer_type) {
	case SESSIONTIMER_TRANS:
		expirer = &expirer_tcp_trans;
		break;
	case SESSIONTIMER_EST:
		expirer = &expirer_tcp_est;
		break;
	case SESSIONTIMER_SYN:
		expirer = &expirer_syn;
		break;
	case SESSIONTIMER_UDP:
		expirer = &expirer_udp;
		break;
	case SESSIONTIMER_ICMP:
		expirer = &expirer_icmp;
		break;
	}
	expirer = set_timer(session, expirer);

	session_get(session); /* We have 3 indexes, but really they count as one. */
	table->count++;
	spin_unlock_bh(&table->lock);

	commit_timer(expirer);

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
		struct ipv4_transport_addr *addr, bool starting)
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

int sessiondb_iterate_by_ipv4(l4_protocol l4_proto, struct ipv4_transport_addr *addr, bool starting,
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

int sessiondb_get_or_create_ipv6(struct tuple *tuple6, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct ipv4_transport_addr local4;
	struct rb_node **node, *parent;
	struct session_table *table;
	struct expire_timer *expirer = NULL;
	int error;

	if (WARN(!tuple6, "There's no session entry mapped to NULL."))
		return -EINVAL;
	if (WARN(tuple6->l4_proto != L4PROTO_UDP && tuple6->l4_proto != L4PROTO_ICMP,
			"I'm a ICMP & UDP function, but I'm handling protocol %u.", tuple6->l4_proto))
		return -EINVAL;

	error = get_session_table(tuple6->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);
	rbtree_find_node(tuple6, &table->tree6, compare_full6, struct session_entry, tree6_hook,
			parent, node);
	if (*node) {
		*session = rb_entry(*node, struct session_entry, tree6_hook);
		goto success;
	}
	/* The entry doesn't exist, so try to create it. */

	/* Translate address from IPv6 to IPv4 */
	error = pool6_get(&tuple6->dst.addr6.l3, &prefix);
	if (error) {
		log_debug("Errcode %d while obtaining %pI6c's prefix.", error, &tuple6->dst.addr6);
		goto fail;
	}

	error = addr_6to4(&tuple6->dst.addr6.l3, &prefix, &local4.l3);
	if (error) {
		log_debug("Error code %d while translating the packet's address.", error);
		goto fail;
	}

	/*
	 * Create the session entry.
	 *
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	local4.l4 = (tuple6->l4_proto != L4PROTO_ICMP) ? tuple6->dst.addr6.l4 : bib->ipv4.l4;
	*session = session_create(&tuple6->src.addr6, &tuple6->dst.addr6, &bib->ipv4, &local4,
			tuple6->l4_proto, bib); /* refcounter = 1*/
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		error = -ENOMEM;
		goto fail;
	}

	/* Add it to the database. */
	rb_link_node(&(*session)->tree6_hook, parent, node);
	rb_insert_color(&(*session)->tree6_hook, &table->tree6);

	error = rbtree_add(*session, *session, &table->tree4, compare_session4, struct session_entry,
			tree4_hook);
	if (WARN(error, "The session entry could be indexed by IPv6, but not by IPv4.")) {
		rb_erase(&(*session)->tree6_hook, &table->tree6);
		session_return(*session);
		goto fail;
	}

	table->count++;
	/* Fall through. */

success:
	switch (tuple6->l4_proto) {
	case L4PROTO_UDP:
		expirer = &expirer_udp;
		break;
	case L4PROTO_ICMP:
		expirer = &expirer_icmp;
		break;
	case L4PROTO_TCP:
	case L4PROTO_OTHER:
		/* handled in a WARN above, not gonna happen. I'm just hushing the compiler. */
		break;
	}

	expirer = set_timer(*session, expirer);
	/* We gotta do this for our caller, because it has to be done before the unlock. */
	session_get(*session);

	spin_unlock_bh(&table->lock);

	commit_timer(expirer);
	return 0;

fail:
	spin_unlock_bh(&table->lock);
	return error;
}


int sessiondb_get_or_create_ipv4(struct tuple *tuple4, struct bib_entry *bib,
		struct session_entry **session)
{
	struct ipv6_prefix prefix;
	struct ipv6_transport_addr remote6;
	struct rb_node **node, *parent;
	struct session_table *table;
	struct expire_timer *expirer = NULL;
	int error;

	if (WARN(!tuple4, "There's no session entry mapped to NULL."))
		return -EINVAL;
	if (WARN(tuple4->l4_proto != L4PROTO_UDP && tuple4->l4_proto != L4PROTO_ICMP,
			"I'm a ICMP & UDP function, but I'm handling protocol %u.", tuple4->l4_proto))
		return -EINVAL;

	error = get_session_table(tuple4->l4_proto, &table);
	if (error)
		return error;

	/* Find it */
	spin_lock_bh(&table->lock);
	rbtree_find_node(tuple4, &table->tree4, compare_full4, struct session_entry, tree4_hook,
			parent, node);
	if (*node) {
		*session = rb_entry(*node, struct session_entry, tree4_hook);
		goto success;
	}
	/* The entry doesn't exist, so try to create it. */

	/* Translate address from IPv4 to IPv6 */
	error = pool6_peek(&prefix);
	if (error)
		goto fail;

	error = addr_4to6(&tuple4->src.addr4.l3, &prefix, &remote6.l3);
	if (error) {
		log_debug("Error code %d while translating the packet's address.", error);
		goto fail;
	}

	/*
	 * Create the session entry.
	 *
	 * Fortunately, ICMP errors cannot reach this code because of the requirements in the header
	 * of section 3.5, so we can use the tuple as shortcuts for the packet's fields.
	 */
	remote6.l4 = (tuple4->l4_proto != L4PROTO_ICMP) ? tuple4->src.addr4.l4 : bib->ipv6.l4;
	*session = session_create(&bib->ipv6, &remote6, &tuple4->dst.addr4, &tuple4->src.addr4,
			tuple4->l4_proto, bib); /* refcounter = 1 */
	if (!(*session)) {
		log_debug("Failed to allocate a session entry.");
		error = -ENOMEM;
		goto fail;
	}

	/* Add it to the database. */
	rb_link_node(&(*session)->tree4_hook, parent, node);
	rb_insert_color(&(*session)->tree4_hook, &table->tree4);

	error = rbtree_add(*session, *session, &table->tree6, compare_session6, struct session_entry,
			tree6_hook);
	if (WARN(error, "The session entry could be indexed by IPv4, but not by IPv6.")) {
		rb_erase(&(*session)->tree4_hook, &table->tree4);
		session_return(*session);
		goto fail;
	}

	table->count++;
	/* Fall through. */

success:
	switch (tuple4->l4_proto) {
	case L4PROTO_UDP:
		expirer = &expirer_udp;
		break;
	case L4PROTO_ICMP:
		expirer = &expirer_icmp;
		break;
	case L4PROTO_TCP:
	case L4PROTO_OTHER:
		/* handled in a WARN above, not gonna happen. I'm just hushing the compiler. */
		break;
	}

	expirer = set_timer(*session, expirer);
	/* We gotta do this for our caller, because it has to be done before the unlock. */
	session_get(*session);

	spin_unlock_bh(&table->lock);

	commit_timer(expirer);
	return 0;

fail:
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
 * Used in delete_sessions_by_prefix4 when is searching in the Session tree4,
 * returns zero if "session"->ipv4.local.address is equals to "prefix" or contains the "prefix".
 * Otherwise return the gap of the comparison result.
 */
static int compare_local_prefix4(const struct session_entry *session,
		const struct ipv4_prefix *prefix)
{
	return (prefix4_contains(prefix, &session->local4.l3))
			? 0
			: ipv4_addr_cmp(&prefix->address, &session->local4.l3);
}

/**
 * Deletes the sessions from the "table" table whose local IPv4 address is "addr".
 * This function is awfully similar to sessiondb_delete_by_bib(). See that for more comments.
 */
static int delete_sessions_by_prefix4(struct session_table *table, struct ipv4_prefix *prefix)
{
	struct session_entry *root_session, *session;
	struct rb_node *node;
	int s = 0;

	spin_lock_bh(&table->lock);

	root_session = rbtree_find(prefix, &table->tree4, compare_local_prefix4, struct session_entry,
			tree4_hook);
	if (!root_session)
		goto success;

	node = rb_prev(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		if (compare_local_prefix4(session, prefix) != 0)
			break;
		s += remove(session, table);

		node = rb_prev(&root_session->tree4_hook);
	}

	node = rb_next(&root_session->tree4_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree4_hook);
		if (compare_local_prefix4(session, prefix) != 0)
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

int sessiondb_delete_by_prefix4(struct ipv4_prefix *prefix)
{
	if (WARN(!prefix, "The IPv4 prefix is NULL"))
		return -EINVAL;

	delete_sessions_by_prefix4(&session_table_tcp, prefix);
	delete_sessions_by_prefix4(&session_table_icmp, prefix);
	delete_sessions_by_prefix4(&session_table_udp, prefix);

	return 0;
}

/**
 * Filtering and updating done during the V4 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_init_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_l3_proto(pkt) == L3PROTO_IPV6 && pkt_tcp_hdr(pkt)->syn) {
		*expirer = set_timer(session, &expirer_tcp_est);
		session->state = ESTABLISHED;
	} /* else, the state remains unchanged. */

	return 0;
}

/**
 * Filtering and updating done during the V6 INIT state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_init_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_tcp_hdr(pkt)->syn) {
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV4:
			*expirer = set_timer(session, &expirer_tcp_est);
			session->state = ESTABLISHED;
			break;
		case L3PROTO_IPV6:
			*expirer = set_timer(session, &expirer_tcp_trans);
			break;
		}
	} /* else, the state remains unchanged */

	return 0;
}

/**
 * Filtering and updating done during the ESTABLISHED state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_established_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_tcp_hdr(pkt)->fin) {
		switch (pkt_l3_proto(pkt)) {
		case L3PROTO_IPV4:
			session->state = V4_FIN_RCV;
			break;
		case L3PROTO_IPV6:
			session->state = V6_FIN_RCV;
			break;
		}

	} else if (pkt_tcp_hdr(pkt)->rst) {
		*expirer = set_timer(session, &expirer_tcp_trans);
		session->state = TRANS;
	} else {
		*expirer = set_timer(session, &expirer_tcp_est);
	}

	return 0;
}

/**
 * Filtering and updating done during the V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_rcv_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_l3_proto(pkt) == L3PROTO_IPV6 && pkt_tcp_hdr(pkt)->fin) {
		*expirer = set_timer(session, &expirer_tcp_trans);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		*expirer = set_timer(session, &expirer_tcp_est);
	}
	return 0;
}

/**
 * Filtering and updating done during the V6 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v6_fin_rcv_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (pkt_l3_proto(pkt) == L3PROTO_IPV4 && pkt_tcp_hdr(pkt)->fin) {
		*expirer = set_timer(session, &expirer_tcp_trans);
		session->state = V4_FIN_V6_FIN_RCV;
	} else {
		*expirer = set_timer(session, &expirer_tcp_est);
	}
	return 0;
}

/**
 * Filtering and updating done during the V6 FIN + V4 FIN RCV state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_v4_fin_v6_fin_rcv_state_handle(struct packet *pkt,
		struct session_entry *session)
{
	return 0; /* Only the timeout can change this state. */
}

/**
 * Filtering and updating done during the TRANS state of the TCP state machine.
 * Part of RFC 6146 section 3.5.2.2.
 */
static int tcp_trans_state_handle(struct packet *pkt, struct session_entry *session,
		struct expire_timer **expirer)
{
	if (!pkt_tcp_hdr(pkt)->rst) {
		*expirer = set_timer(session, &expirer_tcp_est);
		session->state = ESTABLISHED;
	}

	return 0;
}

int sessiondb_tcp_state_machine(struct packet *pkt, struct session_entry *session)
{
	struct expire_timer *expirer = NULL;
	int error;

	spin_lock(&session_table_tcp.lock);

	switch (session->state) {
	case V4_INIT:
		error = tcp_v4_init_state_handle(pkt, session, &expirer);
		break;
	case V6_INIT:
		error = tcp_v6_init_state_handle(pkt, session, &expirer);
		break;
	case ESTABLISHED:
		error = tcp_established_state_handle(pkt, session, &expirer);
		break;
	case V4_FIN_RCV:
		error = tcp_v4_fin_rcv_state_handle(pkt, session, &expirer);
		break;
	case V6_FIN_RCV:
		error = tcp_v6_fin_rcv_state_handle(pkt, session, &expirer);
		break;
	case V4_FIN_V6_FIN_RCV:
		error = tcp_v4_fin_v6_fin_rcv_state_handle(pkt, session);
		break;
	case TRANS:
		error = tcp_trans_state_handle(pkt, session, &expirer);
		break;
	default:
		/*
		 * Because closed sessions are not supposed to be stored,
		 * CLOSED is known to fall through here.
		 */
		WARN(true, "Invalid state found: %u.", session->state);
		error = -EINVAL;
	}

	spin_unlock(&session_table_tcp.lock);

	commit_timer(expirer);

	return error;
}

/**
 * Used in delete_sessions_by_prefix6 when is searching in the Session tree6,
 * returns zero if "session"->ipv6.local.address is equals to "prefix" or contains the "prefix".
 * Otherwise return the gap of the comparison result.
 */
static int compare_local_prefix6(struct session_entry *session, struct ipv6_prefix *prefix)
{
	return (prefix6_contains(prefix, &session->local6.l3))
			? 0
			: ipv6_addr_cmp(&prefix->address, &session->local6.l3);
}

/**
 * Deletes the sessions from the "table" table whose local IPv6 address contains "prefix".
 * This function is awfully similar to sessiondb_delete_by_bib(). See that for more comments.
 */
static int delete_sessions_by_prefix6(struct session_table *table, struct ipv6_prefix *prefix)
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

		if (compare_local_prefix6(session, prefix) != 0)
			break;
		s += remove(session, table);
	}

	node = rb_next(&root_session->tree6_hook);
	while (node) {
		session = rb_entry(node, struct session_entry, tree6_hook);
		node = rb_next(&session->tree6_hook);

		if (compare_local_prefix6(session, prefix) != 0)
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

int sessiondb_delete_by_prefix6(struct ipv6_prefix *prefix)
{
	if (WARN(!prefix, "The IPv6 prefix is NULL"))
		return -EINVAL;

	delete_sessions_by_prefix6(&session_table_tcp, prefix);
	delete_sessions_by_prefix6(&session_table_icmp, prefix);
	delete_sessions_by_prefix6(&session_table_udp, prefix);

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
