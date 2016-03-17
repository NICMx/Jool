#include "nat64/mod/stateful/session/table.h"

#include <linux/version.h>
#include <net/ipv6.h>
#include "nat64/common/constants.h"
#include "nat64/common/session.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/route.h"
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

	if (table->log_changes)
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
		session_put(session, false);
		s++;
	}

	log_debug("Deleted %lu sessions.", s);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
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

static void post_fate(struct net *ns, struct list_head *rms,
		struct list_head *probes)
{
	struct session_entry *session;
	struct session_entry *tmp;

	list_for_each_entry_safe(session, tmp, probes, list_hook) {
		send_probe_packet(ns, session);
		session_put(session, false);
	}

	if (!list_empty(rms))
		delete(rms);
}

static void __clean(struct expire_timer *expirer,
		struct session_table *table,
		struct list_head *rms,
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
		decide_fate(expirer->decide_fate_cb, NULL, table, session, rms,
				probes);
	}
}

void sessiontable_clean(struct session_table *table, struct net *ns)
{
	LIST_HEAD(rms);
	LIST_HEAD(probes);

	spin_lock_bh(&table->lock);
	__clean(&table->est_timer, table, &rms, &probes);
	__clean(&table->trans_timer, table, &rms, &probes);
	spin_unlock_bh(&table->lock);

	post_fate(ns, &rms, &probes);
}

static void init_expirer(struct expire_timer *expirer, int timeout,
		fate_cb decide_fate_cb)
{
	INIT_LIST_HEAD(&expirer->sessions);
	expirer->timeout = msecs_to_jiffies(1000 * timeout);
	expirer->decide_fate_cb = decide_fate_cb;
}

void sessiontable_init(struct session_table *table, fate_cb expired_cb,
		int est_timeout, int trans_timeout)
{
	table->tree6 = RB_ROOT;
	table->tree4 = RB_ROOT;
	table->count = 0;
	init_expirer(&table->est_timer, est_timeout, expired_cb);
	init_expirer(&table->trans_timer, trans_timeout, expired_cb);
	spin_lock_init(&table->lock);
	table->log_changes = DEFAULT_SESSION_LOGGING;
}

/**
 * Auxiliar for sessiondb_destroy(). Wraps the destruction of a session,
 * exposing an API the rbtree module wants.
 *
 * Doesn't care about spinlocks (destructor code doesn't share threads).
 */
static void __destroy_aux(struct rb_node *node)
{
	session_put(rb_entry(node, struct session_entry, tree6_hook), false);
}

void sessiontable_destroy(struct session_table *table)
{
	/*
	 * The values need to be released only in one of the trees
	 * because both trees point to the same values.
	 */
	rbtree_clear(&table->tree6, __destroy_aux);
}

void sessiontable_config_copy(struct session_table *table,
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

void sessiontable_config_set(struct session_table *table,
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

	gap = compare_addr6(&s1->dst6, &s2->dst6);
	if (gap)
		return gap;

	gap = compare_addr6(&s1->src6, &s2->src6);
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

	gap = compare_addr6(&session->dst6, &tuple6->dst.addr6);
	if (gap)
		return gap;

	gap = compare_addr6(&session->src6, &tuple6->src.addr6);
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

	gap = compare_addr4(&s1->src4, &s2->src4);
	if (gap)
		return gap;

	gap = compare_addr4(&s1->dst4, &s2->dst4);
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

	gap = compare_addr4(&session->src4, &tuple4->dst.addr4);
	if (gap)
		return gap;

	gap = ipv4_addr_cmp(&session->dst4.l3, &tuple4->src.addr4.l3);
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

	gap = compare_addr4(&session->src4, &tuple4->dst.addr4);
	if (gap)
		return gap;

	gap = compare_addr4(&session->dst4, &tuple4->src.addr4);
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

/**
 * Important: This particular @cb is not prepared to return FATE_PROBE.
 */
int sessiontable_find(struct session_table *table, struct tuple *tuple,
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

static struct session_entry *add6(struct session_table *table,
		struct session_entry *session)
{
	return rbtree_add(session, session, &table->tree6, compare_session6,
			struct session_entry, tree6_hook);
}

static struct session_entry *add4(struct session_table *table,
		struct session_entry *session)
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
}

/**
 * Important: this particular @cb is not currently prepared to return FATE_RM
 * nor FATE_PROBE.
 */
int sessiontable_add(struct session_table *table, struct session_entry *session,
		fate_cb cb, void *cb_arg)
{
	struct expire_timer *expirer;
	struct session_entry *collision;
	bool est;

	est = session->l4_proto != L4PROTO_TCP || session->state == ESTABLISHED;
	expirer = est ? &table->est_timer : &table->trans_timer;

	spin_lock_bh(&table->lock);

	collision = add6(table, session);
	if (collision)
		goto exists;

	collision = add4(table, session);
	if (collision) {
		rb_erase(&session->tree6_hook, &table->tree6);
		goto exists;
	}

	attach_timer(session, expirer);
	session_get(session); /* Database's references. */
	table->count++;

	if (table->log_changes)
		session_log(session, "Added session");

	spin_unlock_bh(&table->lock);
	return 0;

exists:
	if (cb)
		decide_fate(cb, cb_arg, table, collision, NULL, NULL);
	spin_unlock_bh(&table->lock);
	return -EEXIST;
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

	if (!taddr4_equals(args->addr4, &session->src4))
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

	if (!prefix4_contains(args->prefix, &session->src4.l3))
		return 1; /* positive = break iteration early, no error. */
	if (!port_range_contains(args->ports, session->src4.l4))
		return 0;

	rm(args->table, session, &args->removed);
	return 0;
}

void sessiontable_rm_taddr4s(struct session_table *table,
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
	if (!prefix6_contains(args->prefix, &session->dst6.l3))
		return 1; /* positive = break iteration early, no error. */

	rm(args->table, session, &args->removed);
	return 0;
}

void sessiontable_rm_taddr6s(struct session_table *table,
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
