#include "nat64/mod/pkt_queue.h"
#include "nat64/comm/constants.h"

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/timer.h>
#include <linux/icmp.h>
#include <net/icmp.h>

/********************************************
 * Structures and private variables.
 ********************************************/

/** Cache for struct session_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

/**
 *  Stored packages definition.
 *
 */
struct packet_node {
	/**  */
	struct session_entry *session_entry;

	/**  */
	struct sk_buff *skb;

	/**
	 * Chains this packet with the rest
	 * Used for iterating while looking for expired TCP packets.
	 */
	struct list_head list_hook;
};

/**
 * Chains all known session entries.
 * Currently only used while looking and deleting expired ones.
 */
static LIST_HEAD(all_packets);
static struct timer_list expire_timer;
static DEFINE_SPINLOCK(all_packets_lock);


/********************************************
 * Private (helper) functions.
 ********************************************/
int pktqueue_add(struct session_entry *entry, struct sk_buff *skb)
{
	struct packet_node *node;
	unsigned long expires;

	if (!entry) {
		log_err(ERR_NULL, "Cannot insert NULL as a session entry.");
		return -EINVAL;
	}

	if (!skb) {
		log_err(ERR_NULL, "Cannot insert NULL as a packet.");
		return -EINVAL;
	}

	node = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!node) {
		log_err(ERR_ALLOC_FAILED, "Allocation packet node failed.");
		return -ENOMEM;
	}

	/*TODO: wrapp this function*/
	if (list_empty(&all_packets)) {
//		expires = msecs_to_jiffies(entry->dying_time) + 10;
		expires = entry->dying_time + 10;
		/*TODO: check: on issue 88 session->dying_time is set in jiffies,
		 * but in older code session->dying_time was in msecs, so it's not
		 * necessary to do msecs_to_jiffies for future code I guess...
		 * I don't know what 10 means*/
		mod_timer(&expire_timer, expires);
	}

	node->session_entry = entry;
	node->skb = skb;
	INIT_LIST_HEAD(&node->list_hook);

	spin_lock_bh(&all_packets_lock);
	list_add_tail(&node->list_hook, &all_packets);
	spin_unlock_bh(&all_packets_lock);

	return 0;
}


int pktqueue_remove(void)
{
	struct packet_node *node;

	node = container_of(all_packets.next, struct packet_node, list_hook);
	icmp64_send(node->skb, ICMPERR_PORT_UNREACHABLE, 0);
	list_del(all_packets.next);
	kfree_skb(node->skb);
	kfree(node->session_entry);
	kfree(node);
	return 0;
}

/**
 * Removes from the list the entries whose lifetime has expired. The entries are also freed from
 * memory.
 */
static void clean_expired_packets(void)
{
	struct list_head *current_node, *next_node;
	struct packet_node *packet;
	unsigned int p = 0;
	unsigned int current_time = jiffies_to_msecs(jiffies);
	int error;

	log_debug("Deleting expired TCP packages...");
	spin_lock_bh(&all_packets_lock);

	list_for_each_safe(current_node, next_node, &all_packets) {

		packet = list_entry(current_node, struct packet_node, list_hook);

		/*TODO: check what how is stored packet->session->dying_time if it's in
		 * msecs or in jiffies */
		if (time_before(jiffies, packet->session_entry->dying_time))
			break;

		error = pktqueue_remove();

		if (error) {
			log_crit(ERR_NULL, "The TCP packet could not be removed: %d", error);
			continue;
		}

		p++;
	}

	spin_unlock_bh(&all_packets_lock);
	log_debug("Removed %u TCP packets entries.", p);
}

static void cleaner_timer(unsigned long param)
{
	unsigned long expires;
	struct packet_node *node;

	clean_expired_packets();

	/*TODO: wrapp this function*/
	if (!list_empty(&all_packets))
	{
		spin_lock_bh(&all_packets_lock);

		node = container_of(all_packets.next, struct packet_node, list_hook);
		expires = node->session_entry->dying_time + 10;
//		expires = msecs_to_jiffies(node->session_entry_p->dying_time) + 10;
		/*TODO: check: on issue 88 session->dying_time is set in jiffies,
		 * but in older code session->dying_time was in msecs, so it's not
		 * necessary to do msecs_to_jiffies for future code I guess...
		 * I don't know what 10 means*/
		mod_timer(&expire_timer, expires);

		spin_unlock_bh(&all_packets_lock);
	}
}

int pktqueue_init(void)
{
	entry_cache = kmem_cache_create("jool_pkt_queue", sizeof(struct packet_node),
			0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the Session entry cache.");
		return -ENOMEM;
	}

	init_timer(&expire_timer);
	expire_timer.function = cleaner_timer;
	expire_timer.data = 0;
	expire_timer.expires = 0;

	return 0;
}

void pktqueue_destroy(void)
{
 	int error;

	/* Finish the timer execution */
	del_timer_sync(&expire_timer);

	/* Remove all packets */
	while (!list_empty(&all_packets)) {
		error = pktqueue_remove();
		if (error)
			break;
	}
}
