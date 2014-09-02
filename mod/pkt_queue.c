#include "nat64/mod/pkt_queue.h"
#include "nat64/mod/icmp_wrapper.h"
#include "nat64/mod/rbtree.h"
#include "nat64/comm/constants.h"

#include <linux/printk.h>
#include <linux/timer.h>



/**
 * A stored packet.
 */
struct packet_node {
	/** The packet's session entry. */
	struct session_entry *session;
	/** The packet. */
	struct sk_buff *skb;

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

/** Current valid configuration for this module. */
static struct pktqueue_config *config;


/**
 * Returns a positive integer if node.session.ipv4 < pair.
 * Returns a negative integer if node.session.ipv4 > pair.
 * Returns zero if session.ipv4 == pair.
 *
 * Doesn't care about spinlocks.
 */
static int compare_fn(const struct packet_node *node, const struct ipv4_pair *pair)
{
	int gap;

	gap = ipv4_addr_cmp(&pair->remote.address, &node->session->ipv4.remote.address);
	if (gap != 0)
		return gap;

	gap = pair->remote.l4_id - node->session->ipv4.remote.l4_id;
	if (gap != 0)
		return gap;

	gap = ipv4_addr_cmp(&pair->local.address, &node->session->ipv4.local.address);
	if (gap != 0)
		return gap;

	gap = pair->local.l4_id - node->session->ipv4.local.l4_id;
	return gap;
}

int pktqueue_add(struct session_entry *session, struct sk_buff *skb)
{
	struct packet_node *node;
	unsigned int max_pkts;
	int error;

	if (WARN(!session, "Cannot insert a packet with a NULL session."))
		return -EINVAL;
	if (WARN(!skb, "Cannot insert NULL as a packet."))
		return -EINVAL;

	rcu_read_lock_bh();
	max_pkts = rcu_dereference_bh(config)->max_pkts;
	rcu_read_unlock_bh();

	node = kmem_cache_alloc(node_cache, GFP_ATOMIC);
	if (!node) {
		log_debug("Allocation of packet node failed.");
		return -ENOMEM;
	}

	node->session = session;
	node->skb = skb_original_skb(skb);
	RB_CLEAR_NODE(&node->tree_hook);

	/* Don't need to store fragments other than the first one. */
	kfree_skb_queued(node->skb->next);
	node->skb->next = NULL;

	spin_lock_bh(&packets_lock);

	if (packet_count + 1 >= max_pkts) {
		error = -E2BIG;
		goto fail;
	}

	error = rbtree_add(node, session->ipv4, &packets, compare_fn, struct packet_node, tree_hook);
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

	node = rbtree_find(&session->ipv4, &packets, compare_fn, struct packet_node, tree_hook);
	if (!node) {
		spin_unlock_bh(&packets_lock);
		log_debug("I've been asked to send a packet I don't know.");
		return -ENOENT;
	}

	rb_erase(&node->tree_hook, &packets);
	packet_count--;

	spin_unlock_bh(&packets_lock);

	icmp64_send(node->skb, ICMPERR_PORT_UNREACHABLE, 0);
	kfree_skb_queued(node->skb);
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

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config) {
		kmem_cache_destroy(node_cache);
		return -ENOMEM;
	}
	config->max_pkts = PKTQ_DEF_MAX_STORED_PKTS;

	packets = RB_ROOT;

	return 0;
}

static void pktqueue_destroy_aux(struct rb_node *hook)
{
	struct packet_node *node;
	node = rb_entry(hook, struct packet_node, tree_hook);

	icmp64_send(node->skb, ICMPERR_PORT_UNREACHABLE, 0);
	kfree_skb_queued(node->skb);
	kmem_cache_free(node_cache, node);
}

void pktqueue_destroy(void)
{
	rbtree_clear(&packets, pktqueue_destroy_aux);
	packets.rb_node = NULL;
	kmem_cache_destroy(node_cache);
}

int pktqueue_clone_config(struct pktqueue_config *clone)
{
	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	rcu_read_unlock_bh();
	return 0;
}

int pktqueue_set_config(enum pktqueue_type type, size_t size, void *value)
{
	struct pktqueue_config *tmp_config;
	struct pktqueue_config *old_config;

	if (type != MAX_PKTS) {
		log_err("Unknown config type for the 'packet queue' module: %u", type);
		return -EINVAL;
	}

	if (size != sizeof(__u64)) {
		log_err("Expected an 8-byte integer, got %zu bytes.", size);
		return -EINVAL;
	}

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	tmp_config->max_pkts = *((__u64 *) value);

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();
	kfree(old_config);
	return 0;
}

int pktqueue_remove(struct session_entry *session)
{
	struct packet_node *node;

	if (WARN(!session, "The packet table cannot contain NULL."))
		return -EINVAL;

	spin_lock_bh(&packets_lock);
	node = rbtree_find(&session->ipv4, &packets, compare_fn, struct packet_node, tree_hook);
	if (!node) {
		spin_unlock_bh(&packets_lock);
		return -ENOENT;
	}

	rb_erase(&node->tree_hook, &packets);
	packet_count--;
	spin_unlock_bh(&packets_lock);
	kfree_skb_queued(node->skb);
	session_return(node->session);
	kmem_cache_free(node_cache, node);

	log_debug("Pkt queue - I just cancelled a ICMP error.");
	return 0;
}
