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

	/** Links this packet to the list. See @node_list. */
	struct list_head list_hook;
	/** Links this packet to the tree. See @node_tree. */
	struct rb_node tree_hook;
};

/** Protects @nodes_list, @nodes_tree and @node_count. */
static DEFINE_SPINLOCK(lock);

static unsigned long get_timeout(void)
{
	return msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
}

static void send_icmp_error(struct packet_node *node)
{
	icmp64_send(&node->pkt, ICMPERR_PORT_UNREACHABLE, 0);
	session_put(node->session, false);
	kfree_skb(node->pkt.skb);
	kfree(node);
}

static void rm(struct pktqueue *queue, struct packet_node *node)
{
	list_del(&node->list_hook);
	rb_erase(&node->tree_hook, &queue->node_tree);
	queue->node_count--;
}

void pktqueue_init(struct pktqueue *queue)
{
	INIT_LIST_HEAD(&queue->node_list);
	queue->node_tree = RB_ROOT;
	queue->node_count = 0;
	queue->capacity = DEFAULT_MAX_STORED_PKTS;
}

void pktqueue_destroy(struct pktqueue *queue)
{
	struct packet_node *node;
	struct packet_node *tmp;

	list_for_each_entry_safe(node, tmp, &queue->node_list, list_hook)
		send_icmp_error(node);
}

void pktqueue_config_copy(struct pktqueue *queue, struct pktqueue_config *config)
{
	spin_lock_bh(&lock);
	config->max_stored_pkts = queue->capacity;
	spin_unlock_bh(&lock);
}

void pktqueue_config_set(struct pktqueue *queue, struct pktqueue_config *config)
{
	spin_lock_bh(&lock);
	queue->capacity = config->max_stored_pkts;
	spin_unlock_bh(&lock);
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

static struct packet_node *__tree_add(struct pktqueue *queue,
		struct packet_node *node)
{
	return rbtree_add(node, node->session, &queue->node_tree, compare_fn,
			struct packet_node, tree_hook);
}

int pktqueue_add(struct pktqueue *queue, struct session_entry *session,
		struct packet *pkt)
{
	struct packet_node *node;

	/* Note: this if assumes ICMP errors don't reach this code. */
	if (session->l4_proto != L4PROTO_TCP)
		return 0;

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

	if (queue->node_count + 1 >= queue->capacity) {
		spin_unlock_bh(&lock);
		log_debug("Too many IPv4-initiated TCP connections.");
		/* Fall back to assume there's no Simultaneous Open. */
		icmp64_send(&node->pkt, ICMPERR_PORT_UNREACHABLE, 0);
		kfree(node);
		return -E2BIG;
	}

	if (__tree_add(queue, node)) {
		spin_unlock_bh(&lock);
		log_debug("Simultaneous Open already exists; ignoring packet.");
		kfree(node);
		return -EEXIST;
	}
	list_add_tail(&node->list_hook, &queue->node_list);
	queue->node_count++;

	node = list_entry(queue->node_list.next, typeof(*node), list_hook);

	spin_unlock_bh(&lock);

	/*
	 * I'm assuming caller has a reference; that's why it's legal to do this
	 * outside of the spinlock.
	 */
	session_get(session);

	log_debug("Pkt queue - I just stored a packet.");
	return 0;
}

static struct packet_node *__tree_find(struct pktqueue *queue, struct session_entry *session)
{
	return rbtree_find(session, &queue->node_tree, compare_fn, struct packet_node,
			tree_hook);
}

void pktqueue_rm(struct pktqueue *queue, struct session_entry *session)
{
	struct packet_node *node;

	/* Note: this if assumes ICMP errors don't reach this code. */
	if (session->l4_proto != L4PROTO_TCP)
		return;

	spin_lock_bh(&lock);
	node = __tree_find(queue, session);
	if (!node) {
		spin_unlock_bh(&lock);
		return;
	}

	rm(queue, node);
	spin_unlock_bh(&lock);

	session_put(node->session, false);
	kfree_skb(node->pkt.skb);
	kfree(node);

	log_debug("Pkt queue - I just cancelled an ICMP error.");
}

void pktqueue_clean(struct pktqueue *queue)
{
	struct packet_node *node, *tmp;
	const unsigned long TIMEOUT = get_timeout();
	unsigned long next_timeout;
	LIST_HEAD(icmps);

	log_debug("===============================================");
	log_debug("Handling expired SYN sessions...");

	spin_lock_bh(&lock);
	list_for_each_entry_safe(node, tmp, &queue->node_list, list_hook) {
		/*
		 * "list" is sorted by expiration date,
		 * so stop on the first unexpired session.
		 */
		next_timeout = node->session->update_time + TIMEOUT;
		if (time_before(jiffies, next_timeout))
			break;

		rm(queue, node);
		list_add(&node->list_hook, &icmps);
	}
	spin_unlock_bh(&lock);

	list_for_each_entry_safe(node, tmp, &icmps, list_hook)
		send_icmp_error(node);
}
