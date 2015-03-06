#include "nat64/mod/stateful/pkt_queue.h"
#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/icmp_wrapper.h"
#include "nat64/mod/common/rbtree.h"

#include <linux/printk.h>
#include <linux/timer.h>



/**
 * A stored packet.
 */
struct packet_node {
	/** The packet's session entry. */
	struct session_entry *session;
	/** The packet. */
	struct packet pkt;

	/** Links this packet to the tree. See "packets". */
	struct rb_node tree_hook;
};

/** The same packets, sorted by IPv4 identifiers. */
static struct rb_root packets;
/** Current number of packets in the database. */
static int packet_count = 0;
/** Protects "packets" and "packet_count". */
static DEFINE_SPINLOCK(packets_lock);

/** Cache for struct packet_nodes, for efficient allocation. */
static struct kmem_cache *node_cache;


/**
 * Returns > 0 if node.session.*4 > session.*4.
 * Returns < 0 if node.session.*4 < session.*4.
 * Returns 0 if node.session.*4 == session.*4.
 *
 * Doesn't care about spinlocks.
 */
static int compare_fn(const struct packet_node *node, struct session_entry *session)
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

int pktqueue_add(struct session_entry *session, struct packet *pkt)
{
	struct packet_node *node;
	unsigned int max_pkts;
	int error;

	if (WARN(!session, "Cannot insert a packet with a NULL session."))
		return -EINVAL;
	if (WARN(!pkt, "Cannot insert NULL as a packet."))
		return -EINVAL;

	max_pkts = config_get_max_pkts();

	node = kmem_cache_alloc(node_cache, GFP_ATOMIC);
	if (!node) {
		log_debug("Allocation of packet node failed.");
		return -ENOMEM;
	}

	node->session = session;
	node->pkt = *pkt_original_pkt(pkt);
	RB_CLEAR_NODE(&node->tree_hook);

	spin_lock_bh(&packets_lock);

	if (packet_count + 1 >= max_pkts) {
		error = -E2BIG;
		goto fail;
	}

	error = rbtree_add(node, session, &packets, compare_fn, struct packet_node, tree_hook);
	if (error)
		goto fail;
	packet_count++;

	spin_unlock_bh(&packets_lock);

	session_get(session);
	log_debug("Pkt queue - I just stored a packet.");
	return 0;

fail:
	spin_unlock_bh(&packets_lock);
	kmem_cache_free(node_cache, node);
	log_debug("Someone is trying to force lots of IPv4-TCP connections.");
	return error;
}

int pktqueue_send(struct session_entry *session)
{
	struct packet_node *node;

	if (WARN(!session, "Cannot remove a packet with a NULL session."))
		return -EINVAL;

	spin_lock_bh(&packets_lock);

	node = rbtree_find(session, &packets, compare_fn, struct packet_node, tree_hook);
	if (!node) {
		spin_unlock_bh(&packets_lock);
		log_debug("I've been asked to send a packet I don't know.");
		return -ENOENT;
	}

	rb_erase(&node->tree_hook, &packets);
	packet_count--;

	spin_unlock_bh(&packets_lock);

	icmp64_send(&node->pkt, ICMPERR_PORT_UNREACHABLE, 0);
	kfree_skb(node->pkt.skb);
	session_return(node->session);
	kmem_cache_free(node_cache, node);

	log_debug("Pkt queue - I just sent a ICMP error.");
	return 0;
}

int pktqueue_init(void)
{
	node_cache = kmem_cache_create("jool_pkt_queue", sizeof(struct packet_node), 0, 0, NULL);
	if (!node_cache) {
		log_err("Could not allocate the packet queue's node cache.");
		return -ENOMEM;
	}

	packets = RB_ROOT;

	return 0;
}

static void pktqueue_destroy_aux(struct rb_node *hook)
{
	struct packet_node *node;
	node = rb_entry(hook, struct packet_node, tree_hook);

	icmp64_send(&node->pkt, ICMPERR_PORT_UNREACHABLE, 0);
	kfree_skb(node->pkt.skb);
	kmem_cache_free(node_cache, node);
}

void pktqueue_destroy(void)
{
	rbtree_clear(&packets, pktqueue_destroy_aux);
	packets.rb_node = NULL;
	kmem_cache_destroy(node_cache);
}

int pktqueue_remove(struct session_entry *session)
{
	struct packet_node *node;

	if (WARN(!session, "The packet table cannot contain NULL."))
		return -EINVAL;

	spin_lock_bh(&packets_lock);
	node = rbtree_find(session, &packets, compare_fn, struct packet_node, tree_hook);
	if (!node) {
		spin_unlock_bh(&packets_lock);
		return -ENOENT;
	}

	rb_erase(&node->tree_hook, &packets);
	packet_count--;
	spin_unlock_bh(&packets_lock);
	kfree_skb(node->pkt.skb);
	session_return(node->session);
	kmem_cache_free(node_cache, node);

	log_debug("Pkt queue - I just cancelled a ICMP error.");
	return 0;
}
