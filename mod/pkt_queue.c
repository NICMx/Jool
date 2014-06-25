#include "nat64/mod/pkt_queue.h"
#include "nat64/mod/icmp_wrapper.h"
#include "nat64/mod/rbtree.h"

#include <linux/printk.h>
#include <linux/timer.h>


/**
 * A stored packet.
 */
struct packet_node {
	/** The packet's session entry. */
	struct session_entry *session;
	/** The packet */
	struct sk_buff *skb;

	/** Links this packet to the database. See "packets". */
	struct list_head list_hook;

	/** Appends this entry to the database's IPv4 index. */
	struct rb_node tree4_hook;

};

/** The packets we've stored, and which haven't been yet replied. */
static LIST_HEAD(packets);
/** Current number of nodes in the "packets" list. */
static int packet_count = 0;

/** Cache for struct packet_nodes, for efficient allocation. */
static struct kmem_cache *node_cache;
/** Protects "packets" and "packet_count". */
static DEFINE_SPINLOCK(packets_lock);

/** Current valid configuration for this module. */
static struct pktqueue_config *config;

/** Will awake after a while and reply the "expired" stored packets. */
static struct timer_list expire_timer;

/** Indexes the entries using their IPv4 identifiers. */
static struct rb_root pkt_tree4;

/********************** Private Helper Functions ******************************/

/**
 * Returns a positive integer if session.ipv4.remote < addr.
 * Returns a negative integer if session.ipv4.remote > addr.
 * Returns zero if session.ipv4.local == addr.
 *
 * Doesn't care about spinlocks.
 */
static int compare_remote4(struct session_entry *session, struct ipv4_tuple_address *addr)
{
	int gap;

	gap = ipv4_addr_cmp(&addr->address, &session->ipv4.remote.address);
	if (gap != 0)
		return gap;

	gap = addr->l4_id - session->ipv4.remote.l4_id;
	return gap;
}

/**
 * Returns a positive integer if session.ipv4.remote < addr.
 * Returns a negative integer if session.ipv4.remote > addr.
 * Returns zero if session.ipv4.local == addr.
 *
 * Doesn't care about spinlocks.
 */
static int compare_local4(struct session_entry *session, struct ipv4_tuple_address *addr)
{
	int gap;

	gap = ipv4_addr_cmp(&addr->address, &session->ipv4.local.address);
	if (gap != 0)
		return gap;

	gap = addr->l4_id - session->ipv4.local.l4_id;
	return gap;
}

/**
 * Returns a positive integer if node.session.ipv4 < pair.
 * Returns a negative integer if node.session.ipv4 > pair.
 * Returns zero if session.ipv4 == pair.
 *
 * Doesn't care about spinlocks.
 */
static int compare_full4(struct packet_node *node, struct ipv4_pair *pair)
{
	int gap;

	gap = compare_remote4(node->session, &pair->remote);
	if (gap != 0)
		return gap;

	return compare_local4(node->session, &pair->local);
}


/**
 * Returns the first packet from the "packets" list.
 *
 * Requires packets_lock to already be held (if applies).
 */
static struct packet_node *get_first_pkt(void)
{
	return list_entry(packets.next, struct packet_node, list_hook);
}

int pktqueue_add(struct session_entry *session, struct sk_buff *skb)
{
	int error;
	struct packet_node *node;
	bool start_timer;
	unsigned int max_pkts;

	if (WARN(!session, "Cannot insert NULL as a session entry."))
		return -EINVAL;
	if (WARN(!skb, "Cannot insert NULL as a packet."))
		return -EINVAL;

	rcu_read_lock_bh();
	max_pkts = rcu_dereference_bh(config)->max_pkts;
	rcu_read_unlock_bh();

	if (packet_count >= max_pkts) {
		log_debug("Someone is trying to force lots of simultaneous TCP connections.");
		return -ENOMEM;
	}

	node = kmem_cache_alloc(node_cache, GFP_ATOMIC);
	if (!node) {
		log_debug("Allocation of packet node failed.");
		return -ENOMEM;
	}

	node->session = session;
	node->skb = skb;
	INIT_LIST_HEAD(&node->list_hook);
	RB_CLEAR_NODE(&node->tree4_hook);

	spin_lock_bh(&packets_lock);
	error = rbtree_add(node, session->ipv4, &pkt_tree4, compare_full4, struct packet_node,
			tree4_hook);
	if (error) {
		spin_unlock_bh(&packets_lock);
		log_debug("Someone is trying to force lots of simultaneous TCP connections.");
		kmem_cache_free(node_cache, node);
		return -EINVAL;
	}

	list_add_tail(&node->list_hook, &packets);

	packet_count++;
	start_timer = !timer_pending(&expire_timer);
	spin_unlock_bh(&packets_lock);

	if (start_timer)
		mod_timer(&expire_timer, session->dying_time);

	return 0;
}

/**
 * Sends node's ICMP error, and removes and destroys it.
 */
static void pktqueue_reply(struct packet_node *node)
{
	icmp64_send_skb(node->skb, ICMPERR_PORT_UNREACHABLE, 0);

	rb_erase(&node->tree4_hook, &pkt_tree4);
	list_del(&node->list_hook);
	packet_count--;
	kfree_skb(node->skb);
	session_kfree(node->session);
	kmem_cache_free(node_cache, node);
}

/**
 * Called once in a while by the timer to reply the expired stored packets.
 */
static void reply_fn(unsigned long param)
{
	struct packet_node *node;
	bool start_timer = false;
	unsigned long next_expire;
	unsigned int n = 0;

	log_debug("Replying to stored packets...");
	spin_lock_bh(&packets_lock);

	while (!list_empty(&packets)) {
		node = get_first_pkt();
		next_expire = node->session->dying_time;

		if (time_before(jiffies, next_expire)) {
			start_timer = true;
			/*
			 * The packets are sorted by expiration date, so if this one isn't expired,
			 * the rest will also not be.
			 */
			break;
		}

		pktqueue_reply(node);
		n++;
	}

	spin_unlock_bh(&packets_lock);
	log_debug("Replied %u packets.", n);

	if (start_timer)
		mod_timer(&expire_timer, next_expire);
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

	pkt_tree4 = RB_ROOT;

	init_timer(&expire_timer);
	expire_timer.function = reply_fn;
	expire_timer.data = 0;
	expire_timer.expires = 0;

	return 0;
}

void pktqueue_destroy(void)
{
	del_timer_sync(&expire_timer);

	while (!list_empty(&packets))
		pktqueue_reply(get_first_pkt());

	(&pkt_tree4)->rb_node = NULL;

	kmem_cache_destroy(node_cache);
}

int pktqueue_clone_config(struct pktqueue_config *clone)
{
	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	rcu_read_unlock_bh();
	return 0;
}

int pktqueue_set_config(struct pktqueue_config *new_config)
{
	struct pktqueue_config *tmp_config;
	struct pktqueue_config *old_config;

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	tmp_config->max_pkts = new_config->max_pkts;

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
	node = rbtree_find(&session->ipv4, &pkt_tree4, compare_full4, struct packet_node, tree4_hook);
	if (!node) {
		spin_unlock_bh(&packets_lock);
		return -ENOENT;
	}

	rb_erase(&node->tree4_hook, &pkt_tree4);
	list_del(&node->list_hook);
	packet_count--;
	kfree_skb(node->skb);
	session_kfree(node->session);
	kmem_cache_free(node_cache, node);

	spin_unlock_bh(&packets_lock);

	return 0;
}
