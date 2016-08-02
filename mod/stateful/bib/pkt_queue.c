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
};

static unsigned long get_timeout(void)
{
	return msecs_to_jiffies(1000 * TCP_INCOMING_SYN);
}

static void send_icmp_error(struct pktqueue_session *node)
{
	icmp64_send4(node->skb, ICMPERR_PORT_UNREACHABLE, 0);
	kfree_skb(node->skb);
	wkfree(struct pktqueue_node, node);
}

static void rm(struct pktqueue *queue, struct pktqueue_session *node)
{
	list_del(&node->list_hook);
	rb_erase(&node->tree_hook, &queue->node_tree);
}

struct pktqueue *pktqueue_create(void)
{
	struct pktqueue *result;

	result = wkmalloc(struct pktqueue, GFP_KERNEL);
	if (!result)
		return NULL;

	INIT_LIST_HEAD(&result->node_list);
	result->node_tree = RB_ROOT;

	return result;
}

void pktqueue_destroy(struct pktqueue *queue)
{
	struct pktqueue_session *node;
	struct pktqueue_session *tmp;

	list_for_each_entry_safe(node, tmp, &queue->node_list, list_hook)
		send_icmp_error(node);
	wkfree(struct pktqueue, queue);
}

/**
 * Returns > 0 if node.session.*4 > session.*4.
 * Returns < 0 if node.session.*4 < session.*4.
 * Returns 0 if node.session.*4 == session.*4.
 */
static int compare_fn(const struct pktqueue_session *node,
		const struct ipv6_transport_addr *addr)
{
	return taddr6_compare(&node->dst6, addr);
}

static struct pktqueue_session *__tree_add(struct pktqueue *queue,
		struct pktqueue_session *node)
{
	return rbtree_add(node, &node->dst6, &queue->node_tree, compare_fn,
			struct pktqueue_session, tree_hook);
}

/**
 * On success, assumes the caller's reference to @session is being transferred
 * to @queue.
 */
int pktqueue_add(struct pktqueue *queue, struct packet *pkt,
		struct ipv6_transport_addr *dst6)
{
	struct pktqueue_session *node;
	struct pktqueue_session *collision;

	node = wkmalloc(struct pktqueue_session, GFP_ATOMIC);
	if (!node) {
		log_debug("Allocation of packet node failed.");
		return -ENOMEM;
	}
	node->dst6 = *dst6;
	node->src4 = pkt->tuple.dst.addr4;
	node->dst4 = pkt->tuple.src.addr4;
	node->skb = pkt_original_pkt(pkt)->skb;
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

	log_debug("Pkt queue - I just stored a packet.");
	return 0;
}

static struct pktqueue_session *__tree_find(struct pktqueue *queue,
		struct ipv6_transport_addr *addr)
{
	return rbtree_find(addr, &queue->node_tree, compare_fn,
			struct pktqueue_session, tree_hook);
}

struct pktqueue_session *pktqueue_find(struct pktqueue *queue,
		struct ipv6_transport_addr *addr,
		struct mask_domain *masks)
{
	struct pktqueue_session *node;

	node = __tree_find(queue, addr);
	if (!node)
		return NULL;

	if (!mask_domain_matches(masks, &node->src4))
		return NULL;

	rm(queue, node);
	return node;
}

void pktqueue_put_node(struct pktqueue_session *node)
{
	kfree_skb(node->skb);
	wkfree(struct pktqueue_session, node);
}

void pktqueue_prepare_clean(struct pktqueue *queue, struct list_head *probes)
{
	struct pktqueue_session *node, *tmp;
	const unsigned long TIMEOUT = get_timeout();

	list_for_each_entry_safe(node, tmp, &queue->node_list, list_hook) {
		/*
		 * "list" is sorted by expiration date,
		 * so stop on the first unexpired session.
		 */
		if (time_before(jiffies, node->update_time + TIMEOUT))
			break;

		rm(queue, node);
		list_add(&node->list_hook, probes);
	}
}

void pktqueue_clean(struct list_head *probes)
{
	struct pktqueue_session *node, *tmp;
	list_for_each_entry_safe(node, tmp, probes, list_hook)
		send_icmp_error(node);
}
