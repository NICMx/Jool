#include "nat64/mod/stateful/bib/pkt_queue.h"

#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/rbtree.h"
#include "nat64/mod/common/wkmalloc.h"

struct pktqueue {
	struct list_head node_list;
	/** The same packets, sorted by IPv4 identifiers. */
	struct rb_root node_tree;
	/** Current number of packets in the database. */
	int node_count;

	unsigned int capacity;
};

/**
 * A stored packet.
 */
struct pktqueue_node {
	/** The packet's session entry. */
	struct pktqueue_session session;
	unsigned long update_time;
	/** The packet. */
	struct packet pkt;

	/** Links this packet to the list. See @node_list. */
	struct list_head list_hook;
	/** Links this packet to the tree. See @node_tree. */
	struct rb_node tree_hook;
};

static unsigned long get_timeout(void)
{
	return msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
}

static void send_icmp_error(struct pktqueue_node *node)
{
	icmp64_send(&node->pkt, ICMPERR_PORT_UNREACHABLE, 0);
	kfree_skb(node->pkt.skb);
	wkfree(struct pktqueue_node, node);
}

static void rm(struct pktqueue *queue, struct pktqueue_node *node)
{
	list_del(&node->list_hook);
	rb_erase(&node->tree_hook, &queue->node_tree);
	queue->node_count--;
}

struct pktqueue *pktqueue_create(void)
{
	struct pktqueue *result;

	result = wkmalloc(struct pktqueue, GFP_KERNEL);
	if (!result)
		return NULL;

	INIT_LIST_HEAD(&result->node_list);
	result->node_tree = RB_ROOT;
	result->node_count = 0;
	result->capacity = DEFAULT_MAX_STORED_PKTS;

	return result;
}

void pktqueue_destroy(struct pktqueue *queue)
{
	struct pktqueue_node *node;
	struct pktqueue_node *tmp;

	list_for_each_entry_safe(node, tmp, &queue->node_list, list_hook)
		send_icmp_error(node);
	wkfree(struct pktqueue, queue);
}

void pktqueue_config_copy(struct pktqueue *queue,
		struct pktqueue_config *config)
{
	config->max_stored_pkts = queue->capacity;
}

void pktqueue_config_set(struct pktqueue *queue, struct pktqueue_config *config)
{
	queue->capacity = config->max_stored_pkts;
}

/**
 * Returns > 0 if node.session.*4 > session.*4.
 * Returns < 0 if node.session.*4 < session.*4.
 * Returns 0 if node.session.*4 == session.*4.
 *
 * Doesn't care about spinlocks.
 */
static int compare_fn(const struct pktqueue_node *node,
		const struct pktqueue_session *session)
{
	int gap;

	gap = taddr4_compare(&node->session.src4, &session->src4);
	if (gap)
		return gap;

	return taddr4_compare(&node->session.dst4, &session->dst4);
}

static struct pktqueue_node *__tree_add(struct pktqueue *queue,
		struct pktqueue_node *node)
{
	return rbtree_add(node, &node->session, &queue->node_tree, compare_fn,
			struct pktqueue_node, tree_hook);
}

/**
 * On success, assumes the caller's reference to @session is being transferred
 * to @queue.
 */
int pktqueue_add(struct pktqueue *queue, struct pktqueue_session *session,
		struct packet *pkt)
{
	struct pktqueue_node *node;
	struct pktqueue_node *collision;

	if (queue->node_count + 1 >= queue->capacity) {
		log_debug("Too many IPv4-initiated TCP connections.");
		/* Fall back to assume there's no Simultaneous Open. */
		/* TODO ... this is happening in a lock */
		icmp64_send(pkt, ICMPERR_PORT_UNREACHABLE, 0);
		return -E2BIG;
	}

	node = wkmalloc(struct pktqueue_node, GFP_ATOMIC);
	if (!node) {
		log_debug("Allocation of packet node failed.");
		return -ENOMEM;
	}
	node->session = *session;
	node->pkt = *pkt_original_pkt(pkt);
	node->pkt.original_pkt = &node->pkt;
	RB_CLEAR_NODE(&node->tree_hook);

	collision = __tree_add(queue, node);
	if (collision) {
		log_debug("Simultaneous Open already exists.");
		wkfree(struct pktqueue_node, node);

		collision->update_time = jiffies;
		list_del(&collision->list_hook);
		list_add_tail(&collision->list_hook, &queue->node_list);

		return -EEXIST;
	}

	list_add_tail(&node->list_hook, &queue->node_list);
	queue->node_count++;

	log_debug("Pkt queue - I just stored a packet.");
	return 0;
}

static struct pktqueue_node *__tree_find(struct pktqueue *queue,
		struct pktqueue_session *session)
{
	return rbtree_find(session, &queue->node_tree, compare_fn,
			struct pktqueue_node, tree_hook);
}

/**
 * Why?
 * RFC 6146 insists on us storing src6 and dst6 and I can't find any other use
 * for them.
 * Also if pool6 changes I don't want the wrong v4 endnode to get the ICMP
 * error somehow.
 * Or pool4 changes and @src6 no longer is the owner of @src4.
 */
static bool pqsession_equals6(struct pktqueue_session *s1,
		struct pktqueue_session *s2)
{
	if (s1->src6_set && !taddr6_equals(&s1->src6, &s2->src6))
		return false;
	return taddr6_equals(&s1->dst6, &s2->dst6);
}

void pktqueue_rm(struct pktqueue *queue, struct pktqueue_session *session)
{
	struct pktqueue_node *node;

	node = __tree_find(queue, session);
	if (!node || !pqsession_equals6(&node->session, session))
		return;

	rm(queue, node);
	kfree_skb(node->pkt.skb);
	wkfree(struct pktqueue_node, node);

	log_debug("Pkt queue - I just cancelled an ICMP error.");
}

void pktqueue_clean(struct pktqueue *queue)
{
	struct pktqueue_node *node, *tmp;
	const unsigned long TIMEOUT = get_timeout();
	unsigned long next_timeout;
	LIST_HEAD(icmps);

	list_for_each_entry_safe(node, tmp, &queue->node_list, list_hook) {
		/*
		 * "list" is sorted by expiration date,
		 * so stop on the first unexpired session.
		 */
		next_timeout = node->update_time + TIMEOUT;
		if (time_before(jiffies, next_timeout))
			break;

		rm(queue, node);
		list_add(&node->list_hook, &icmps);
	}

	list_for_each_entry_safe(node, tmp, &icmps, list_hook)
		send_icmp_error(node);
}
