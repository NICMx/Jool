#include "receiver.h"

#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/spinlock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/list.h>

#include "types.h"
#include "skb_ops.h"
#include "device_name.h"

static struct skb_user_db skb_ipv4_db;
static struct skb_user_db skb_ipv6_db;

struct skb_user_db {
	/* The root of the DB. */
	struct list_head list;
	/* Counter to know how many skb we have in the DB.*/
	__u8 counter;
	/* Counter to know when an incoming and an stored skb are the same.*/
	__u8 success_comparison;
	/* Counter to know when an incoming and an stored skb are not the same, either the incoming
	 * packet or the stored packet is wrong.*/
	__u8 fail_comparison;
	/* A lock to prevent concurrent access.*/
	spinlock_t lock;
};

struct skb_entry {
	/* skb created from user app.*/
	struct sk_buff *skb;
	/* The filename from the user app. */
	char *file_name;
	/* A pointer in the database.*/
	struct list_head list;
};

static void delete_skb_entry(struct skb_entry *entry)
{
	kfree(entry->file_name);
	skb_free(entry->skb);
	list_del(&entry->list);
	kfree(entry);
	return;
}

/**
 * Store a packet from the user app.
 */
int handle_skb_from_user(struct sk_buff *skb, char *usr_file_name, __u32 str_len)
{
	struct skb_entry *entry;
	struct skb_user_db *skb_db;
	char *file_name;

	entry = kmalloc(sizeof(struct skb_entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;
	file_name = kmalloc(str_len, GFP_ATOMIC);
	if (!file_name)
		return -ENOMEM;

	memcpy(file_name, usr_file_name, str_len);
	entry->skb = skb;
	entry->file_name = file_name;

	if (skb->protocol == htons(ETH_P_IP)) {
		skb_db = &skb_ipv4_db;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		skb_db = &skb_ipv6_db;
	} else {
		log_err("skb from user space have no protocol assigned.");
		kfree(file_name);
		kfree(entry);
		return -EINVAL;
	}

	spin_lock_bh(&skb_db->lock);
	list_add_tail(&entry->list, &skb_db->list);
	skb_db->counter++;
	spin_unlock_bh(&skb_db->lock);

	return 0;
}

int receiver_init(void)
{
	skb_ipv4_db.counter = 0;
	skb_ipv4_db.fail_comparison = 0;
	skb_ipv4_db.success_comparison = 0;
	INIT_LIST_HEAD(&skb_ipv4_db.list);
	spin_lock_init(&skb_ipv4_db.lock);

	skb_ipv6_db.counter = 0;
	skb_ipv6_db.fail_comparison = 0;
	skb_ipv6_db.success_comparison = 0;
	INIT_LIST_HEAD(&skb_ipv6_db.list);
	spin_lock_init(&skb_ipv6_db.lock);

	return 0;
}

static void destroy_aux(struct skb_user_db *skb_db)
{
	struct list_head *current_hook, *next_hook;
	struct skb_entry *skb_usr;

	list_for_each_safe(current_hook, next_hook, &skb_db->list) {
		skb_usr = list_entry(current_hook, struct skb_entry, list);
		delete_skb_entry(skb_usr);
	}
}

int receiver_flush_db(void)
{
	destroy_aux(&skb_ipv4_db);
	destroy_aux(&skb_ipv6_db);

	return 0;
}

void receiver_destroy(void)
{
	destroy_aux(&skb_ipv4_db);
	destroy_aux(&skb_ipv6_db);

	receiver_display_stats();
}

int receiver_display_stats(void)
{
	log_info("IPv4 Stats");
	log_info("    Successes: %u", skb_ipv4_db.success_comparison);
	log_info("    Failures:  %u", skb_ipv4_db.fail_comparison);
	log_info("    Not found: %u", skb_ipv4_db.counter);
	log_info("IPv6 Stats");
	log_info("    Successes: %u", skb_ipv6_db.success_comparison);
	log_info("    Failures:  %u", skb_ipv6_db.fail_comparison);
	log_info("    Not found: %u", skb_ipv6_db.counter);
	return 0;
}
