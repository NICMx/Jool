#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/stats.h"
#include "nat64/mod/common/packet.h"

#include <linux/version.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>

struct reassembly_buffer {
	/** first fragment (fragment offset zero) of the packet. */
	struct packet pkt;
	/** This points to the place the next frament should be queued. */
	struct sk_buff **next_slot;
	/* Jiffy at which the fragment timer will delete this buffer. */
	unsigned long dying_time;

	struct list_head list_hook;
};

/** Cache for struct reassembly_buffers, for efficient allocation. */
static struct kmem_cache *buffer_cache;

#define HTABLE_NAME fragdb_table
#define KEY_TYPE struct packet
#define VALUE_TYPE struct reassembly_buffer
#define HASH_TABLE_SIZE 256
#include "../common/hash_table.c"

/**
 * Just a random number, initialized at startup.
 * Used to prevent attackers from crafting special packets that will have the same hash code but
 * different hash slots. See
 * http://stackoverflow.com/questions/12175109/why-does-the-linux-ipv4-stack-need-random-numbers.
 */
static u32 rnd;

static struct fragdb_table table;
static DEFINE_SPINLOCK(table_lock);

static struct timer_list expire_timer;
static LIST_HEAD(expire_list);


/**
 * As specified above, the database is (mostly) a hash table. This is one of two functions used
 * internally by the table to search for values.
 */
static bool equals_function(const struct packet *key1, const struct packet *key2)
{
	struct ipv6hdr *hdr1 = pkt_ip6_hdr(key1);
	struct ipv6hdr *hdr2 = pkt_ip6_hdr(key2);

	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	if (!addr6_equals(&hdr1->saddr, &hdr2->saddr))
		return false;
	if (!addr6_equals(&hdr1->daddr, &hdr2->daddr))
		return false;
	if (pkt_frag_hdr(key1)->identification != pkt_frag_hdr(key2)->identification)
		return false;
	if (pkt_l4_proto(key1) != pkt_l4_proto(key2))
		return false;

	return true;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
/**
 * Hash function for IPv6 keys from reassembly.c
 */
static unsigned int inet6_hash_frag(__be32 id, const struct in6_addr *saddr,
		const struct in6_addr *daddr, u32 rnd)
{
	u32 c;
	c = jhash_3words(ipv6_addr_hash(saddr), ipv6_addr_hash(daddr), (__force u32)id, rnd);
	return c & (INETFRAGS_HASHSZ - 1);
}
#endif

/**
 * As specified above, the database is a hash table. This is one of two functions used internally
 * by the table to search for values.
 */
static unsigned int hash_function(const struct packet *key)
{
	struct ipv6hdr *hdr = pkt_ip6_hdr(key);
	return inet6_hash_frag(pkt_frag_hdr(key)->identification, &hdr->saddr, &hdr->daddr, rnd);
}

#define COMMON_MSG " Looks like nf_defrag_ipv6 is not sorting the fragments, " \
		"or something's shuffling them later. Please report."
static struct reassembly_buffer *add_pkt(struct packet *pkt)
{
	struct reassembly_buffer *buffer;
	struct frag_hdr *hdr_frag = pkt_frag_hdr(pkt);
	unsigned int payload_len;

	/* Does it already exist? If so, add to and return existing buffer */
	buffer = fragdb_table_get(&table, pkt);
	if (buffer) {
		if (WARN(is_first_frag6(hdr_frag), "Non-first fragment's offset is zero." COMMON_MSG))
			return NULL;

		*buffer->next_slot = pkt->skb;
		buffer->next_slot = &pkt->skb->next;

		/* Why this? Dunno, both defrags do it when they support frag_list. */
		/*
		 * Note, since we're in the middle of its sort of initialization, pkt is illegal at this
		 * point. It looks like we should call pkt_payload_len_frag() instead of
		 * pkt_payload_len_pkt(), but that's not the case because it represents a subsequent
		 * fragment. Be careful with the calculation of this length.
		 */
		payload_len = pkt_payload_len_pkt(pkt);
		buffer->pkt.skb->len += payload_len;
		buffer->pkt.skb->data_len += payload_len;
		buffer->pkt.skb->truesize += pkt->skb->truesize;
		skb_pull(pkt->skb, pkt_hdrs_len(pkt));

		return buffer;
	}

	if (WARN(!is_first_frag6(hdr_frag), "First fragment's offset is nonzero." COMMON_MSG))
		return NULL;

	/*
	 * TODO (fine) Maybe pskb_expand_head() can be used here as fallback.
	 * I decided to leave this as is for the moment because it's such an
	 * obnoxious ridiculous corner case scenario and it will probably never
	 * cause any problems.
	 * Until somebody complains, I think I should probably work on more
	 * pressing stuff.
	 * I learned about pskb_expand_head() in the defrag modules.
	 */
	if (skb_cloned(pkt->skb)) {
		log_debug("Packet is cloned, so I can't edit its shared area. Canceling translation.");
		return NULL;
	}

	/* Create buffer, add the packet to it, index */
	buffer = kmem_cache_alloc(buffer_cache, GFP_ATOMIC);
	if (!buffer)
		return NULL;

	buffer->pkt = *pkt;
	buffer->pkt.original_pkt = &buffer->pkt;
	buffer->next_slot = &skb_shinfo(pkt->skb)->frag_list;
	buffer->dying_time = jiffies + config_get_ttl_frag();

	if (is_error(fragdb_table_put(&table, pkt, buffer))) {
		kmem_cache_free(buffer_cache, buffer);
		return NULL;
	}

	/* Schedule for automatic deletion */
	list_add(&buffer->list_hook, expire_list.prev);
	if (!timer_pending(&expire_timer)) {
		mod_timer(&expire_timer, buffer->dying_time);
		log_debug("The fragment cleaning timer will awake in %u msecs.",
				jiffies_to_msecs(expire_timer.expires - jiffies));
	}

	return buffer;
}
#undef COMMON_MSG

static void buffer_dealloc(struct reassembly_buffer *buffer)
{
	kfree_skb(buffer->pkt.skb);
	kmem_cache_free(buffer_cache, buffer);
}

/**
 * Removes "buffer" from the database and destroys it.
 */
static void buffer_destroy(struct reassembly_buffer *buffer, struct packet *pkt)
{
	if (WARN(!fragdb_table_remove(&table, pkt, NULL),
			"Something is attempting to delete a buffer that wasn't stored in the database."))
		return;

	list_del(&buffer->list_hook);
	buffer_dealloc(buffer);
}

/**
 * Core of the cleaner_timer() function, intended to actually clean the database from obsolete
 * fragments.
 */
static void clean_expired_buffers(void)
{
	unsigned int b = 0;
	struct reassembly_buffer *buffer;

	log_debug("Deleting expired reassembly buffers...");

	spin_lock_bh(&table_lock);

	while (!list_empty(&expire_list)) {
		buffer = list_entry(expire_list.next, struct reassembly_buffer, list_hook);

		if (time_after(buffer->dying_time, jiffies)) {
			spin_unlock_bh(&table_lock);
			log_debug("Deleted %u reassembly buffers.", b);
			return;
		}

		buffer_destroy(buffer, &buffer->pkt);
		b++;
	}

	spin_unlock_bh(&table_lock);
	log_debug("Deleted %u reassembly buffers. The database is now empty.", b);
}

/**
 * Executed by the kernel every once in a while to exterminate expired fragments.
 */
static void cleaner_timer(unsigned long param)
{
	struct reassembly_buffer *buffer;
	unsigned long next_expire;
	unsigned long min_time = jiffies + MIN_TIMER_SLEEP;

	clean_expired_buffers();

	spin_lock_bh(&table_lock);

	if (list_empty(&expire_list)) {
		spin_unlock_bh(&table_lock);
		/* No need to re-schedule the timer. */
		return;
	}

	/* Restart the timer. */
	buffer = list_entry(expire_list.next, struct reassembly_buffer, list_hook);
	next_expire = buffer->dying_time;
	spin_unlock_bh(&table_lock);

	if (next_expire < min_time)
		next_expire = min_time;

	mod_timer(&expire_timer, next_expire);
}

/**
 * Call during initialization for the remaining functions to work properly.
 */
int fragdb_init(void)
{
	int error;

	/* TODO test again siit doesn't modprobe these. */
	nf_defrag_ipv6_enable();
	nf_defrag_ipv4_enable();

	buffer_cache = kmem_cache_create("jool_reassembly_buffers", sizeof(struct reassembly_buffer),
			0, 0, NULL);
	if (!buffer_cache) {
		log_err("Could not allocate the reassembly buffer cache.");
		return -ENOMEM;
	}

	error = fragdb_table_init(&table, equals_function, hash_function);
	if (error) {
		kmem_cache_destroy(buffer_cache);
		return error;
	}

	init_timer(&expire_timer);
	expire_timer.function = cleaner_timer;
	expire_timer.expires = 0;
	expire_timer.data = 0;

	get_random_bytes(&rnd, sizeof(rnd));

	return 0;
}

#define COMMON_MSG " I will not be able to translate; aborting.\n" \
		"(I don't this error is going to happen... but if it does, either some future kernel " \
		"version broke our assumptions or there is a kernel module in prerouting (pre-Jool), " \
		"which is doing some questionable edits on the packet.)"
/**
 * This whole module is a hack that tries to leverage nf_defrag_ipv6's hack, but we can't do it if
 * there are more hacks on top of it.
 * Therefore additional validations.
 */
static int validate_skb(struct sk_buff *skb)
{
	if (WARN(skb->prev || skb->next, "Packet is listed." COMMON_MSG))
		return -EINVAL;

	if (WARN(skb_shinfo(skb)->frag_list, "Packet has a fragment list." COMMON_MSG))
		return -EINVAL;

	return 0;
}
#undef COMMON_MSG

/**
 * Groups "skb_in" with the rest of its fragments.
 * If the rest of the fragments have not yet arrived, this will return VER_STOLEN and store skb_in.
 * If all of the fragments have arrived, this will return VER_CONTINUE and the zero-offset fragment
 * will be returned in "skb_out". The rest of the fragments can be accesed via skb_out's list
 * (skb_shinfo(skb_out)->frag_list).
 */
verdict fragdb_handle(struct packet *pkt)
{
	/* The fragment collector skb belongs to. */
	struct reassembly_buffer *buffer;
	struct frag_hdr *hdr_frag = pkt_frag_hdr(pkt);
	int error;

	if (!is_fragmented_ipv6(hdr_frag))
		return VERDICT_CONTINUE;

	/*
	 * Because the packet *is* fragmented, we know we're being compiled in kernel 3.12 or lower at
	 * this point.
	 * (Other defragmenters conceal the fragment header, effectively pretending there's no
	 * fragmentation.)
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	WARN(true, "This code is supposed to be unreachable in kernels 3.13+! Please report.");
	return VERDICT_DROP;
#endif

	log_debug("Adding fragment to database.");

	error = validate_skb(pkt->skb);
	if (error)
		return VERDICT_DROP;

	spin_lock_bh(&table_lock);

	buffer = add_pkt(pkt);
	if (!buffer) {
		spin_unlock_bh(&table_lock);
		return VERDICT_DROP;
	}

	/*
	 * nf_defrag_ipv6 is supposed to sort the fragments, so this condition should be all we need
	 * to figure out whether we have all the fragments.
	 * Otherwise we'd need to keep track of holes. If you ever find yourself needing to add hole
	 * logic, keep in mind that this module used to do that in Jool 3.2, so you might be able
	 * to reuse it.
	 */
	if (is_mf_set_ipv6(hdr_frag)) {
		spin_unlock_bh(&table_lock);
		return VERDICT_STOLEN;
	}

	*pkt = buffer->pkt;
	pkt->original_pkt = pkt;
	buffer->pkt.skb = NULL;
	/* Note, at this point, buffer->pkt is invalid. Do not use. */
	buffer_destroy(buffer, pkt);
	spin_unlock_bh(&table_lock);

	if (!skb_make_writable(pkt->skb, pkt_l3hdr_len(pkt)))
		return VERDICT_DROP;
	/* Why this? Dunno, both defrags do it when they support frag_list. */
	pkt_ip6_hdr(pkt)->payload_len = cpu_to_be16(pkt->skb->len - sizeof(struct ipv6hdr));
	/*
	 * The kernel's defrag also removes the fragment header.
	 * That actually harms us, so we don't mirror it. Instead, we make the fragment atomic.
	 * The rest of Jool must assume the packet might have a redundant fragment header.
	 */
	pkt_frag_hdr(pkt)->frag_off &= cpu_to_be16(~IP6_MF);

	log_debug("All the fragments are now available. Resuming translation...");
	return VERDICT_CONTINUE;
}

/**
 * Empties the database, freeing memory. Call during destruction to avoid memory leaks.
 */
void fragdb_destroy(void)
{
	del_timer_sync(&expire_timer);
	fragdb_table_empty(&table, buffer_dealloc);
	kmem_cache_destroy(buffer_cache);
}
