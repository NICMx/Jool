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

/**
 *  Stored packages definition.
 *
 */
struct packet_node {
	/**  */
	struct session_entry *session_entry_p;

	/**  */
	struct sk_buff *skb;

	/**
	 * Chains this packet with the rest
	 * Used for iterating while looking for expired TCP packets.
	 */
	struct list_head list_hook;

	/** Millisecond (from the epoch) this packet should expire in, if still inactive. */
	unsigned int dying_time;
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

	node = kmalloc(sizeof(struct packet_node), GFP_ATOMIC);

	if (!node) {
		log_err(ERR_ALLOC_FAILED, "Allocation packet node failed.");
		return -ENOMEM;
	}

	if(list_empty(&all_packets)){
		expires = jiffies + msecs_to_jiffies(SESSION_TIMER_INTERVAL);
		mod_timer(&expire_timer, expires);
	}

	node->session_entry_p = entry;
	node->skb = skb;
	node->dying_time = entry->dying_time;
	INIT_LIST_HEAD(&node->list_hook);

	spin_lock_bh(&all_packets_lock);
	list_add_tail(&node->list_hook, &all_packets);
	spin_unlock_bh(&all_packets_lock);

	return 0;
}


int pktqueue_remove(void)
{
	struct packet_node *node;
	node = container_of(all_packets.prev, struct packet_node, list_hook);
	icmp_send(node->skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
    list_del(all_packets.prev);
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

		if (packet->dying_time > current_time)
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

	if(!list_empty(&all_packets))
	{
		node = container_of(all_packets.next, struct packet_node, list_hook);
		expires = jiffies + msecs_to_jiffies(node->dying_time);
		mod_timer(&expire_timer, expires);
	}
}

int pktqueue_init(void)
{

	init_timer(&expire_timer);
	expire_timer.function = cleaner_timer;
	expire_timer.data = 0;

	return 0;
}

void pktqueue_destroy(void)
{
 	int error;

	//Finish the timer execution
	del_timer_sync(&expire_timer);

	//Remove all packets
	spin_lock_bh(&all_packets_lock);
	while (!list_empty(&all_packets)) {
		error = pktqueue_remove();
		if(error)
			break;
	}
	spin_unlock_bh(&all_packets_lock);
}
