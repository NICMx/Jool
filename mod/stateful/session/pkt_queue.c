#include "nat64/mod/stateful/session/pkt_queue.h"

#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/rbtree.h"

/**
 * A stored packet.
 */
struct packet_node {
	/** The packet's session entry. */
	struct session_entry *session;
	/** The packet. */
	struct packet pkt;

	/** Links this packet to the list. See @nodes_list. */
	struct list_head list_hook;
	/** Links this packet to the tree. See @nodes_tree. */
	struct rb_node tree_hook;
};

static struct list_head node_list;
/** The same packets, sorted by IPv4 identifiers. */
static struct rb_root node_tree;
/** Current number of packets in the database. */
static int node_count;
/** Protects @nodes_list, @nodes_tree and @node_count. */
static DEFINE_SPINLOCK(lock);

static struct timer_list timer;

static unsigned long get_timeout(void)
{
	return msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
}

static void send_icmp_error(struct packet_node *node)
{
	icmp64_send(&node->pkt, ICMPERR_PORT_UNREACHABLE, 0);
	session_return(node->session);
	kfree_skb(node->pkt.skb);
	kfree(node);
}

static void rm(struct packet_node *node)
{
	list_del(&node->list_hook);
	rb_erase(&node->tree_hook, &node_tree);
	node_count--;
}

static void cleaner_timer(unsigned long param)
{
	struct packet_node *node, *tmp;
	const unsigned long TIMEOUT = get_timeout();
	unsigned long next_timeout;
	LIST_HEAD(icmps);

	log_debug("===============================================");
	log_debug("Handling expired SYN sessions...");

	spin_lock_bh(&lock);
	list_for_each_entry_safe(node, tmp, &node_list, list_hook) {
		/*
		 * "list" is sorted by expiration date,
		 * so stop on the first unexpired session.
		 */
		next_timeout = node->session->update_time + TIMEOUT;
		if (time_before(jiffies, next_timeout)) {
			mod_timer(&timer, next_timeout);
			break;
		}

		rm(node);
		list_add(&node->list_hook, &icmps);
	}
	spin_unlock_bh(&lock);

	list_for_each_entry_safe(node, tmp, &icmps, list_hook)
		send_icmp_error(node);
}

int pktqueue_init(void)
{
	INIT_LIST_HEAD(&node_list);
	node_tree = RB_ROOT;
	node_count = 0;

	init_timer(&timer);
	timer.function = cleaner_timer;
	timer.expires = 0;
	timer.data = 0;

	return 0;
}

void pktqueue_destroy(void)
{
	struct packet_node *node, *tmp;

	del_timer_sync(&timer);

	/* TODO (issue36) I think this might be untested. */
	/* TODO (issue36) Also test pktqueue w/hairpinning. */
	list_for_each_entry_safe(node, tmp, &node_list, list_hook)
		send_icmp_error(node);
}

/**
 * Returns > 0 if node.session.*4 > session.*4.
 * Returns < 0 if node.session.*4 < session.*4.
 * Returns 0 if node.session.*4 == session.*4.
 *
 * Doesn't care about spinlocks.
 */
static int compare_fn(const struct packet_node *node,
		const struct session_entry *session)
{
	int gap;

	gap = ipv4_addr_cmp(&node->session->remote4.l3, &session->remote4.l3);
	if (gap)
		return gap;

	gap = node->session->remote4.l4 - session->remote4.l4;
	if (gap)
		return gap;

	gap = ipv4_addr_cmp(&node->session->local4.l3, &session->local4.l3);
	if (gap)
		return gap;

	gap = node->session->local4.l4 - session->local4.l4;
	return gap;
}

static int __tree_add(struct packet_node *node)
{
	return rbtree_add(node, node->session, &node_tree, compare_fn,
			struct packet_node, tree_hook);
}

int pktqueue_add(struct session_entry *session, struct packet *pkt)
{
	struct packet_node *node;
	int error;

	node = kmalloc(sizeof(*node), GFP_ATOMIC);
	if (!node) {
		log_debug("Allocation of packet node failed.");
		return -ENOMEM;
	}
	node->session = session;
	node->pkt = *pkt_original_pkt(pkt);
	node->pkt.original_pkt = &node->pkt;
	RB_CLEAR_NODE(&node->tree_hook);

	spin_lock_bh(&lock);

	if (node_count + 1 >= config_get_max_pkts()) {
		spin_unlock_bh(&lock);
		log_debug("Too many IPv4-initiated TCP connections.");
		/* Fall back to assume there's no Simultaneous Open. */
		icmp64_send(&node->pkt, ICMPERR_PORT_UNREACHABLE, 0);
		kfree(node);
		return -E2BIG;
	}

	error = __tree_add(node);
	if (error) {
		spin_unlock_bh(&lock);
		log_debug("Simultaneous Open already exists; ignoring packet.");
		kfree(node);
		return error;
	}
	list_add_tail(&node->list_hook, &node_list);
	node_count++;

	node = list_entry(node_list.next, typeof(*node), list_hook);
	mod_timer(&timer, node->session->update_time + get_timeout());

	spin_unlock_bh(&lock);

	/*
	 * I'm assuming caller has a reference; that's why it's legal to do this
	 * outside of the spinlock.
	 */
	session_get(session);

	log_debug("Pkt queue - I just stored a packet.");
	return 0;
}

static struct packet_node *__tree_find(struct session_entry *session)
{
	return rbtree_find(session, &node_tree, compare_fn, struct packet_node,
			tree_hook);
}

void pktqueue_remove(struct session_entry *session)
{
	struct packet_node *node;

	if (WARN(!session, "The packet table cannot contain NULL."))
		return;

	spin_lock_bh(&lock);
	node = __tree_find(session);
	if (!node) {
		spin_unlock_bh(&lock);
		return;
	}

	rm(node);
	spin_unlock_bh(&lock);

	session_return(node->session);
	kfree_skb(node->pkt.skb);
	kfree(node);

	log_debug("Pkt queue - I just cancelled an ICMP error.");
}
