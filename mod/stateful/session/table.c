#include "nat64/mod/stateful/session/table.h"

#include <net/ipv6.h>
#include "nat64/common/constants.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/session/pkt_queue.h"

/**
 * Removes all of this database's references towards "session", and drops its
 * refcount accordingly.
 *
 * "table"'s spinlock must already be held.
 */
static void rm(struct session_table *table, struct session_entry *session,
		struct list_head *rms)
{
	if (!WARN(RB_EMPTY_NODE(&session->tree6_hook), "Faulty IPv6 index"))
		rb_erase(&session->tree6_hook, &table->tree6);
	if (!WARN(RB_EMPTY_NODE(&session->tree4_hook), "Faulty IPv4 index"))
		rb_erase(&session->tree4_hook, &table->tree4);
	table->count--;
	list_del(&session->list_hook);
	list_add(&session->list_hook, rms);
	session->expirer = NULL;

	session_log(session, "Forgot session");
}

static void delete(struct list_head *sessions)
{
	struct session_entry *session;
	unsigned long s = 0;

	while (!list_empty(sessions)) {
		session = list_entry(sessions->next, typeof(*session),
				list_hook);
		list_del(&session->list_hook);
		session_return(session);
		s++;
	}

	log_debug("Deleted %lu sessions.", s);
}

/**
 * Spinlock must be held.
 */
static void force_reschedule(struct expire_timer *expirer)
{
	struct session_entry *first;
	unsigned long next_time;
	const unsigned long min_next_time = jiffies + MIN_TIMER_SLEEP;

	if (list_empty(&expirer->sessions))
		return;

	first = list_entry(expirer->sessions.next, typeof(*first), list_hook);

	next_time = first->update_time + atomic_read(&expirer->timeout);

	if (time_before(next_time, min_next_time))
		next_time = min_next_time;

	mod_timer(&expirer->timer, next_time);
	log_debug("Timer will awake in %u msecs.",
			jiffies_to_msecs(expirer->timer.expires - jiffies));
}

/**
 * Spinlock must be held.
 */
static void reschedule(struct expire_timer *expirer)
{
	/*
	 * Any existing sessions will expire before the new one (because they
	 * are sorted that way).
	 * The timer should always trigger on the earliest session.
	 */
	if (timer_pending(&expirer->timer))
		return;

	force_reschedule(expirer);
}

void sessiontable_reschedule(struct expire_timer *expirer)
{
	reschedule(expirer);
}

static void decide_fate(fate_cb cb,
		void *cb_arg,
		struct session_table *table,
		struct session_entry *session,
		struct list_head *rms,
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
		reschedule(&table->est_timer);
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
		/*  Fall through. */
	case FATE_TIMER_TRANS:
		session->update_time = jiffies;
		session->expirer = &table->trans_timer;
		list_del(&session->list_hook);
		list_add_tail(&session->list_hook, &session->expirer->sessions);
		reschedule(&table->trans_timer);
		break;
	case FATE_RM:
		rm(table, session, rms);
		break;
	case FATE_PRESERVE:
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

	th->check = csum_ipv6_magic(&iph->saddr, &iph->daddr, l4_hdr_len,
			IPPROTO_TCP, csum_partial(th, l4_hdr_len, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	pkt_fill(&pkt, skb, L3PROTO_IPV6, L4PROTO_TCP, NULL, th + 1, NULL);

	if (!route6(ns, &pkt)) {
		kfree_skb(skb);
		goto fail;
	}

	error = ip6_local_out(skb); /* Implicit kfree_skb(skb) goes here. */
	if (error) {
		log_debug("ip6_local_out returned errcode %d.", error);
		goto fail;
	}

	return;

fail:
	log_debug("A TCP connection will probably break.");
}

static void post_fate(struct net *ns, struct list_head *rms,
		struct list_head *probes)
{
	struct session_entry *session;
	struct session_entry *tmp;

	list_for_each_entry_safe(session, tmp, probes, list_hook) {
		send_probe_packet(ns, session);
		session_return(session);
	}

	if (!list_empty(rms))
		delete(rms);
}

/* TODO call this. */
void sessiontable_clean(struct session_table *table,
		struct net *ns,
		struct list_head *sessions,
		unsigned long timeout,
		fate_cb decide_fate_cb)
{
	struct session_entry *session;
	struct session_entry *tmp;
	LIST_HEAD(rms);
	LIST_HEAD(probes);

	spin_lock_bh(&table->lock);
	list_for_each_entry_safe(session, tmp, sessions, list_hook) {
		/*
		 * "list" is sorted by expiration date,
		 * so stop on the first unexpired session.
		 */
		if (time_before(jiffies, session->update_time + timeout))
			break;

		decide_fate(decide_fate_cb, NULL, table, session, &rms, &probes);
	}
	spin_unlock_bh(&table->lock);

	post_fate(ns, &rms, &probes);
}

/**
 * Called once in a while to kick off the scheduled expired sessions massacre.
 *
 * In that sense, it's a public function, so it requires spinlocks to NOT be
 * held.
 */
static void cleaner_timer(unsigned long param)
{

}

static void init_expirer(struct expire_timer *expirer,
		int timeout, fate_cb decide_fate_cb,
		struct session_table *table)
{
	init_timer(&expirer->timer);
	expirer->timer.function = cleaner_timer;
	expirer->timer.expires = 0;
	expirer->timer.data = (unsigned long) expirer;
	INIT_LIST_HEAD(&expirer->sessions);
	atomic_set(&expirer->timeout, msecs_to_jiffies(1000 * timeout));
	expirer->decide_fate_cb = decide_fate_cb;
	expirer->table = table;
}

void sessiontable_init(struct session_table *table,
		int est_timeout, fate_cb est_callback,
		int trans_timeout, fate_cb trans_callback)
{
	table->tree6 = RB_ROOT;
	table->tree4 = RB_ROOT;
	table->count = 0;
	init_expirer(&table->est_timer, est_timeout, est_callback, table);
	init_expirer(&table->trans_timer, trans_timeout, trans_callback, table);
	spin_lock_init(&table->lock);
	atomic_set(&table->log_changes, DEFAULT_SESSION_LOGGING);
}

/**
 * Auxiliar for sessiondb_destroy(). Wraps the destruction of a session,
 * exposing an API the rbtree module wants.
 *
 * Doesn't care about spinlocks (destructor code doesn't share threads).
 */
static void __destroy_aux(struct rb_node *node)
{
	session_return(rb_entry(node, struct session_entry, tree6_hook));
}

void sessiontable_destroy(struct session_table *table)
{
	del_timer_sync(&table->est_timer.timer);
	del_timer_sync(&table->trans_timer.timer);
	/*
	 * The values need to be released only in one of the trees
	 * because both trees point to the same values.
	 */
	rbtree_clear(&table->tree6, __destroy_aux);
}

static int compare_addr6(const struct ipv6_transport_addr *a1,
		const struct ipv6_transport_addr *a2)
{
	int gap;

	gap = ipv6_addr_cmp(&a1->l3, &a2->l3);
	if (gap)
		return gap;

	gap = a1->l4 - a2->l4;
	return gap;
}

static int compare_session6(const struct session_entry *s1,
		const struct session_entry *s2)
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
static int compare_full6(const struct session_entry *session,
		const struct tuple *tuple6)
{
	int gap;

	gap = compare_addr6(&session->local6, &tuple6->dst.addr6);
	if (gap)
		return gap;

	gap = compare_addr6(&session->remote6, &tuple6->src.addr6);
	return gap;
}

static int compare_addr4(const struct ipv4_transport_addr *a1,
		const struct ipv4_transport_addr *a2)
{
	int gap;

	gap = ipv4_addr_cmp(&a1->l3, &a2->l3);
	if (gap)
		return gap;

	gap = a1->l4 - a2->l4;
	return gap;
}

static int compare_session4(const struct session_entry *s1,
		const struct session_entry *s2)
{
	int gap;

	gap = compare_addr4(&s1->local4, &s2->local4);
	if (gap)
		return gap;

	gap = compare_addr4(&s1->remote4, &s2->remote4);
	return gap;
}

/**
 * Returns > 0 if session.*4 > tuple4.*.addr4.
 * Returns < 0 if session.*4 < tuple4.*.addr4.
 * Returns 0 if session.*4 == tuple4.*.addr4.
 *
 * It excludes remote layer-4 IDs from the comparison.
 * See sessiondb_allow() to find out why.
 *
 * Doesn't care about spinlocks.
 */
static int compare_addrs4(const struct session_entry *session,
		const struct tuple *tuple4)
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
static int compare_full4(const struct session_entry *session,
		const struct tuple *tuple4)
{
	int gap;

	gap = compare_addr4(&session->local4, &tuple4->dst.addr4);
	if (gap)
		return gap;

	gap = compare_addr4(&session->remote4, &tuple4->src.addr4);
	return gap;
}

static struct session_entry *get_by_ipv6(struct session_table *table,
		struct tuple *tuple)
{
	return rbtree_find(tuple, &table->tree6, compare_full6,
			struct session_entry, tree6_hook);
}

static struct session_entry *get_by_ipv4(struct session_table *table,
		struct tuple *tuple)
{
	return rbtree_find(tuple, &table->tree4, compare_full4,
			struct session_entry, tree4_hook);
}

int sessiontable_get(struct session_table *table, struct tuple *tuple,
		fate_cb cb, void *cb_arg,
		struct session_entry **result)
{
	struct session_entry *session;
	LIST_HEAD(rms);
	LIST_HEAD(probes);

	spin_lock_bh(&table->lock);

	switch (tuple->l3_proto) {
	case L3PROTO_IPV6:
		session = get_by_ipv6(table, tuple);
		break;
	case L3PROTO_IPV4:
		session = get_by_ipv4(table, tuple);
		break;
	default:
		WARN(true, "Unsupported network protocol: %u", tuple->l3_proto);
		spin_unlock_bh(&table->lock);
		return -EINVAL;
	}

	if (session) {
		session_get(session);
		if (cb)
			decide_fate(cb, cb_arg, table, session, &rms, &probes);
	}

	spin_unlock_bh(&table->lock);

	if (cb)
		post_fate(NULL, &rms, &probes);

	if (!session)
		return -ESRCH;

	*result = session;
	return 0;
}

bool sessiontable_allow(struct session_table *table, struct tuple *tuple4)
{
	struct session_entry *session;
	bool result;

	spin_lock_bh(&table->lock);
	session = rbtree_find(tuple4, &table->tree4, compare_addrs4,
			struct session_entry, tree4_hook);
	result = session ? true : false;
	spin_unlock_bh(&table->lock);

	return result;
}

static int add6(struct session_table *table, struct session_entry *session)
{
	return rbtree_add(session, session, &table->tree6, compare_session6,
			struct session_entry, tree6_hook);
}

static int add4(struct session_table *table, struct session_entry *session)
{
	return rbtree_add(session, session, &table->tree4, compare_session4,
			struct session_entry, tree4_hook);
}

static void attach_timer(struct session_entry *session,
		struct expire_timer *expirer)
{
	session->update_time = jiffies;
	list_add_tail(&session->list_hook, &expirer->sessions);
	session->expirer = expirer;
	reschedule(expirer);
}

int sessiontable_add(struct session_table *table, struct session_entry *session,
		bool is_established, bool is_synchronized)
{
	struct expire_timer *expirer;
	int error;

	expirer = is_established ? &table->est_timer : &table->trans_timer;


	spin_lock_bh(&table->lock);


	error = add6(table, session);
	if (error) {
		spin_unlock_bh(&table->lock);
		return error;
	}


	error = add4(table, session);
	if (error) {
		rb_erase(&session->tree6_hook, &table->tree6);
		spin_unlock_bh(&table->lock);
		return error;
	}

	attach_timer(session, expirer);
	session_get(session); /* Database's references. */
	table->count++;


	spin_unlock_bh(&table->lock);

	if (atomic_read(&table->log_changes))
		session_log(session, "Added session");

	//function to add session for synchronization.

	if (!is_synchronized)
	error = joold_add_session_element(session);


	return 0;
}

/**
 * Requires "table"'s spinlock to already be held.
 */
static struct rb_node *find_starting_point(struct session_table *table,
		const struct ipv4_transport_addr *offset_remote,
		const struct ipv4_transport_addr *offset_local,
		const bool include_offset)
{
	struct rb_node **node, *parent;
	struct session_entry *session;
	struct tuple offset;

	/* If there's no offset, start from the beginning. */
	if (!offset_remote || !offset_local)
		return rb_first(&table->tree4);

	/* If offset is found, start from offset or offset's next. */
	offset.src.addr4 = *offset_remote;
	offset.dst.addr4 = *offset_local; /* the protos are not needed. */
	rbtree_find_node(&offset, &table->tree4, compare_full4,
			struct session_entry, tree4_hook, parent, node);
	if (*node)
		return include_offset ? (*node) : rb_next(*node);

	if (!parent)
		return NULL;

	/*
	 * If offset is not found, start from offset's next anyway.
	 * (If offset was meant to exist, it probably timed out and died while
	 * the caller wasn't holding the spinlock; it's nothing to worry about.)
	 */
	session = rb_entry(parent, struct session_entry, tree4_hook);
	return (compare_full4(session, &offset) < 0) ? rb_next(parent) : parent;
}

static int __foreach(struct session_table *table,
		int (*func)(struct session_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset_remote,
		const struct ipv4_transport_addr *offset_local,
		const bool include_offset)
{
	struct rb_node *node, *next;
	struct session_entry *session;
	int error = 0;
	spin_lock_bh(&table->lock);

	node = find_starting_point(table, offset_remote, offset_local,
			include_offset);
	for (; node && !error; node = next) {
		next = rb_next(node);
		session = rb_entry(node, struct session_entry, tree4_hook);
		error = func(session, arg);
	}

	spin_unlock_bh(&table->lock);
	return error;
}

int sessiontable_foreach(struct session_table *table,
		int (*func)(struct session_entry *, void *), void *arg,
		const struct ipv4_transport_addr *offset_remote,
		const struct ipv4_transport_addr *offset_local)
{
	return __foreach(table, func, arg, offset_remote, offset_local, false);
}

int sessiontable_count(struct session_table *table, __u64 *result)
{
	spin_lock_bh(&table->lock);
	*result = table->count;
	spin_unlock_bh(&table->lock);
	return 0;
}

struct bib_remove_args {
	struct session_table *table;
	const struct ipv4_transport_addr *addr4;
	struct list_head removed;
};

static int __rm_by_bib(struct session_entry *session, void *args_void)
{
	struct bib_remove_args *args = args_void;

	if (!ipv4_transport_addr_equals(args->addr4, &session->local4))
		return 1; /* positive = break iteration early, no error. */

	rm(args->table, session, &args->removed);
	return 0;
}

void sessiontable_delete_by_bib(struct session_table *table,
		struct bib_entry *bib)
{
	struct bib_remove_args args = {
			.table = table,
			.addr4 = &bib->ipv4,
			.removed = LIST_HEAD_INIT(args.removed),
	};
	struct ipv4_transport_addr remote = {
			.l3.s_addr = 0,
			.l4 = 0,
	};

	__foreach(table, __rm_by_bib, &args, &remote, &bib->ipv4, true);
	delete(&args.removed);
}

struct taddr4_remove_args {
	struct session_table *table;
	const struct ipv4_prefix *prefix;
	const struct port_range *ports;
	struct list_head removed;
};

static int __rm_taddr4s(struct session_entry *session, void *args_void)
{
	struct taddr4_remove_args *args = args_void;

	if (!prefix4_contains(args->prefix, &session->local4.l3))
		return 1; /* positive = break iteration early, no error. */
	if (!port_range_contains(args->ports, session->local4.l4))
		return 0;

	rm(args->table, session, &args->removed);
	return 0;
}

void sessiontable_delete_taddr4s(struct session_table *table,
		struct ipv4_prefix *prefix, struct port_range *ports)
{
	struct taddr4_remove_args args = {
			.table = table,
			.prefix = prefix,
			.ports = ports,
			.removed = LIST_HEAD_INIT(args.removed),
	};
	struct ipv4_transport_addr remote = {
			.l3.s_addr = 0,
			.l4 = 0,
	};
	struct ipv4_transport_addr local = {
			.l3 = prefix->address,
			.l4 = ports->min,
	};

	__foreach(table, __rm_taddr4s, &args, &remote, &local, true);
	delete(&args.removed);
}

/**
 * Requires "table"'s spinlock to already be held.
 */
static struct rb_node *find_starting_point6(struct session_table *table,
		const struct ipv6_transport_addr *local)
{
	struct rb_node **node, *parent;
	struct session_entry *session;
	struct tuple offset;

	memset(&offset.src.addr6, 0, sizeof(offset.src.addr6));
	offset.dst.addr6 = *local;
	/* the protos are not needed. */

	rbtree_find_node(&offset, &table->tree6, compare_full6,
			struct session_entry, tree6_hook, parent, node);
	if (*node)
		return *node;

	if (!parent)
		return NULL;

	session = rb_entry(parent, struct session_entry, tree6_hook);
	return (compare_full6(session, &offset) < 0) ? rb_next(parent) : parent;
}

struct taddr6_remove_args {
	struct session_table *table;
	const struct ipv6_prefix *prefix;
	struct list_head removed;
};

static int __rm_taddr6s(struct session_entry *session,
		struct taddr6_remove_args *args)
{
	if (!prefix6_contains(args->prefix, &session->local6.l3))
		return 1; /* positive = break iteration early, no error. */

	rm(args->table, session, &args->removed);
	return 0;
}

void sessiontable_delete_taddr6s(struct session_table *table,
		struct ipv6_prefix *prefix)
{
	struct taddr6_remove_args args = {
			.table = table,
			.prefix = prefix,
			.removed = LIST_HEAD_INIT(args.removed),
	};
	struct ipv6_transport_addr local = {
			.l3 = prefix->address,
			.l4 = 0,
	};
	struct rb_node *node, *next;
	struct session_entry *session;
	int error = 0;
	spin_lock_bh(&table->lock);

	node = find_starting_point6(table, &local);
	for (; node && !error; node = next) {
		next = rb_next(node);
		session = rb_entry(node, struct session_entry, tree6_hook);
		error = __rm_taddr6s(session, &args);
	}

	spin_unlock_bh(&table->lock);
	delete(&args.removed);
}

struct flush_args {
	struct session_table *table;
	struct list_head removed;
};

static int __flush(struct session_entry *session, void *args_void)
{
	struct flush_args *args = args_void;
	rm(args->table, session, &args->removed);
	return 0;
}

void sessiontable_flush(struct session_table *table)
{
	struct flush_args args = {
			.table = table,
			.removed = LIST_HEAD_INIT(args.removed),
	};

	__foreach(table, __flush, &args, NULL, NULL, 0);
	delete(&args.removed);
}

void sessiontable_update_timers(struct session_table *table)
{
	spin_lock_bh(&table->lock);
	force_reschedule(&table->est_timer);
	force_reschedule(&table->trans_timer);
	spin_unlock_bh(&table->lock);
}
