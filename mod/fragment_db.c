#include "nat64/mod/fragment_db.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/stats.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/random.h"

#include <linux/version.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

struct reassembly_buffer_key {
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	__be32 identification;
	enum l4_protocol l4_proto;
};

struct reassembly_buffer {
	/** first fragment (fragment offset zero) of the packet. */
	struct sk_buff *skb;
	/** This points to the place the next frament should be queued. */
	struct sk_buff **next_slot;
	/* Jiffy at which the fragment timer will delete this buffer. */
	unsigned long dying_time;

	struct list_head list_hook;
};

/** Cache for struct reassembly_buffers, for efficient allocation. */
static struct kmem_cache *buffer_cache;

#define HTABLE_NAME fragdb_table
#define KEY_TYPE struct reassembly_buffer_key
#define VALUE_TYPE struct reassembly_buffer
#include "hash_table.c"

/**
 * Just a random number, initialized at startup.
 * Used to prevent attackers from crafting special packets that will have the same hash code but
 * different hash slots. See
 * http://stackoverflow.com/questions/12175109/why-does-the-linux-ipv4-stack-need-random-numbers.
 */
static u32 rnd;

static struct fragdb_table table;
static DEFINE_SPINLOCK(table_lock);

static struct fragmentation_config *config;

static struct timer_list expire_timer;
static LIST_HEAD(expire_list);


/**
 * Synchronization-safely returns the current configuration's fragment timeout.
 * fragment timeout is the maximum time any fragment should remain in memory. If that much time has
 * passed, it's most likely because at least one of its siblings died during shipping, and as such
 * reassembly is impossible.
 */
static unsigned long get_fragment_timeout(void)
{
	unsigned long result;

	rcu_read_lock_bh();
	result = rcu_dereference_bh(config)->fragment_timeout;
	rcu_read_unlock_bh();

	return result;
}

/**
 * As specified above, the database is (mostly) a hash table. This is one of two functions used
 * internally by the table to search for values.
 */
static bool equals_function(const struct reassembly_buffer_key *key1,
		const struct reassembly_buffer_key *key2)
{
	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	if (!ipv6_addr_equals(&key1->src_addr, &key2->src_addr))
		return false;
	if (!ipv6_addr_equals(&key1->dst_addr, &key2->dst_addr))
		return false;
	if (key1->identification != key2->identification)
		return false;
	if (key1->l4_proto != key2->l4_proto)
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
static unsigned int hash_function(const struct reassembly_buffer_key *key)
{
	return inet6_hash_frag(key->identification, &key->src_addr, &key->dst_addr, rnd);
}

/**
 * Just a one-liner for populating reassembly_buffer_keys.
 */
static int skb_to_key(struct sk_buff *skb, struct frag_hdr *hdr_frag,
		struct reassembly_buffer_key *key)
{
	struct ipv6hdr *hdr6 = ipv6_hdr(skb);

	if (!hdr_frag) {
		hdr_frag = get_extension_header(hdr6, NEXTHDR_FRAGMENT);
		if (WARN(!hdr_frag, "Stored fragment has no fragment header."))
			return -EINVAL;
	}

	key->src_addr = hdr6->saddr;
	key->dst_addr = hdr6->daddr;
	key->identification = hdr_frag->identification;
	key->l4_proto = skb_l4_proto(skb);

	return 0;
}

/**
 * Returns the reassembly buffer described by "key" from the database.
 */
static struct reassembly_buffer *buffer_get(struct reassembly_buffer_key *key)
{
	struct reassembly_buffer *buffer;

	/* Does it already exist? If so, return existing buffer */
	buffer = fragdb_table_get(&table, key);
	if (buffer)
		return buffer;

	/* Create, index */
	buffer = kmem_cache_alloc(buffer_cache, GFP_ATOMIC);
	if (!buffer)
		return NULL;
	buffer->skb = NULL;
	buffer->next_slot = NULL;
	buffer->dying_time = jiffies + get_fragment_timeout();

	if (is_error(fragdb_table_put(&table, key, buffer))) {
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

static void buffer_dealloc(struct reassembly_buffer *buffer)
{
	kfree_skb(buffer->skb);
	kmem_cache_free(buffer_cache, buffer);
}

/**
 * Removes "buffer" from the database and destroys it.
 *
 * "key" is assumed to have been constructed from "buffer"; it is not inferred internally for silly
 * performance reasons.
 */
static void buffer_destroy(struct reassembly_buffer_key *key, struct reassembly_buffer *buffer)
{
	bool success;

	/* Remove it from the DB. */
	success = fragdb_table_remove(&table, key, NULL);
	if (WARN(!success, "Something is attempting to delete a buffer that wasn't stored "
			"in the database."))
		return;

	list_del(&buffer->list_hook);

	/* Deallocate it. */
	buffer_dealloc(buffer);
}

/**
 * Core of the cleaner_timer() function, intended to actually clean the database from obsolete
 * fragments.
 */
static void clean_expired_buffers(void)
{
	unsigned int b = 0;
	struct reassembly_buffer_key key;
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

		if (!is_error(skb_to_key(buffer->skb, NULL, &key))) {
			buffer_destroy(&key, buffer);
			b++;
		}
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

	config = kmalloc(sizeof(*config), GFP_ATOMIC);

	if (!config) {
		log_err("Could not allocate memory to store the fragmentation config.");
		return -ENOMEM;
	}
	config->fragment_timeout = msecs_to_jiffies(1000 * FRAGMENT_MIN);

	buffer_cache = kmem_cache_create("jool_reassembly_buffers", sizeof(struct reassembly_buffer),
			0, 0, NULL);
	if (!buffer_cache) {
		log_err("Could not allocate the reassembly buffer cache.");
		kfree(config);
		return -ENOMEM;
	}

	error = fragdb_table_init(&table, equals_function, hash_function);
	if (error) {
		kmem_cache_destroy(buffer_cache);
		kfree(config);
		return error;
	}

	init_timer(&expire_timer);
	expire_timer.function = cleaner_timer;
	expire_timer.expires = 0;
	expire_timer.data = 0;

	rnd = get_random_u32();

	return 0;
}

/**
 * Copies this module's current configuration to "clone".
 *
 * @param[out] clone a copy of the current config will be placed here. Must be already allocated.
 * @return zero on success, nonzero on failure.
 */
int fragdb_clone_config(struct fragmentation_config *clone)
{
	rcu_read_lock_bh();
	*clone = *rcu_dereference_bh(config);
	rcu_read_unlock_bh();

	return 0;
}

/**
 * Updates the configuration of this module.
 *
 * @param[in] operation indicator of which fields from "new_config" should be taken into account.
 * @param[in] new configuration values.
 * @return zero on success, nonzero on failure.
 */
int fragdb_set_config(enum fragmentation_type type, size_t size, void *value)
{
	struct fragmentation_config *tmp_config;
	struct fragmentation_config *old_config;
	__u64 value64;
	__u32 max_u32 = 0xFFFFFFFFL; /* Max value in milliseconds */
	unsigned long fragment_min = msecs_to_jiffies(1000 * FRAGMENT_MIN);

	if (type != FRAGMENT_TIMEOUT) {
		log_err("Unknown config type for the 'fragment db' module: %u", type);
		return -EINVAL;
	}

	if (size != sizeof(__u64)) {
		log_err("Expected an 8-byte integer, got %zu bytes.", size);
		return -EINVAL;
	}

	value64 = *((__u64 *) value);
	if (value64 > max_u32) {
		log_err("Expected a timeout less than %u seconds", max_u32 / 1000);
		return -EINVAL;
	}

	value64 = msecs_to_jiffies(value64);
	if (value64 < fragment_min) {
		log_err("The fragment timeout must be at least %u seconds.", FRAGMENT_MIN);
		return -EINVAL;
	}

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	tmp_config->fragment_timeout = value64;

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();
	kfree(old_config);
	return 0;
}

#define COMM_MSG " Looks like nf_defrag_ipv6 is not sorting the fragments, " \
		"or something's shuffling them later. Please report."
static int buffer_add_frag(struct reassembly_buffer *buffer, struct sk_buff *frag,
		struct frag_hdr *hdr_frag)
{
	if (buffer->skb) {
		if (WARN(is_first_fragment_ipv6(hdr_frag), "Non-first fragment's offset is zero." COMM_MSG))
			return -EINVAL;

		/*
		 * TODO (issue #41) we're editing the skbs, including the shared area, which means we
		 * should probably be cloning. Do it later; I can test as it is.
		 */

		*buffer->next_slot = frag;
		buffer->next_slot = &frag->next;

		/* Why this? Dunno, both defrags do it when they support frag_list. */
		buffer->skb->len += skb_payload_len_frag(frag);
		buffer->skb->data_len += skb_payload_len_frag(frag);
		buffer->skb->truesize += frag->truesize;

	} else {
		if (WARN(!is_first_fragment_ipv6(hdr_frag), "First fragment's offset is nonzero." COMM_MSG))
			return -EINVAL;

		buffer->skb = frag;
		buffer->next_slot = &skb_shinfo(frag)->frag_list;
	}

	return 0;
}
#undef COMM_MSG

#define COMM_MSG " I will not be able to translate; aborting.\n" \
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
	if (WARN(skb->prev || skb->next, "Packet is listed." COMM_MSG))
		return -EINVAL;

	if (WARN(skb_shinfo(skb)->frag_list, "Packet has a fragment list." COMM_MSG))
		return -EINVAL;

	return 0;
}
#undef COMM_MSG

/**
 * Groups "skb_in" with the rest of its fragments.
 * If the rest of the fragments have not yet arrived, this will return VER_STOLEN and store skb_in.
 * If all of the fragments have arrived, this will return VER_CONTINUE and the zero-offset fragment
 * will be returned in "skb_out". The rest of the fragments can be accesed via skb_out's list
 * (skb_shinfo(skb_out)->frag_list).
 */
verdict fragdb_handle(struct sk_buff **skb)
{
	/* The fragment collector skb belongs to. */
	struct reassembly_buffer *buffer;
	/* This is just a helper that allows us to quickly find buffer. */
	struct reassembly_buffer_key key;
	struct frag_hdr *hdr_frag = get_extension_header(ipv6_hdr(*skb), NEXTHDR_FRAGMENT);
	int error;

	if (!is_fragmented_ipv6(hdr_frag))
		return VER_CONTINUE;

	/*
	 * Because the packet *is* fragmented, we know we're being compiled in kernel 3.12 or lower at
	 * this point.
	 * (Other defragmenters conceal the fragment header, effectively pretending there's no
	 * fragmentation.)
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	WARN(true, "This code is supposed to be unreachable in kernels 3.13+! Please report.");
	return VER_DROP;
#endif

	error = validate_skb(*skb);
	if (error)
		return VER_DROP;

	error = skb_to_key(*skb, hdr_frag, &key);
	if (error)
		return VER_DROP;

	spin_lock_bh(&table_lock);

	buffer = buffer_get(&key);
	if (!buffer)
		goto lock_fail;

	error = buffer_add_frag(buffer, *skb, hdr_frag);
	if (error)
		goto lock_fail;

	/*
	 * nf_defrag_ipv6 is supposed to sort the fragments, so this condition should be all we need
	 * to figure out whether we have all the fragments.
	 * Otherwise we'd need to keep track of holes. If you ever find yourself needing to add hole
	 * logic, keep in mind that this module used to do that in Jool 3.2.2, so you might be able
	 * to reuse it.
	 */
	if (is_more_fragments_set_ipv6(hdr_frag)) {
		spin_unlock_bh(&table_lock);
		return VER_STOLEN;
	}

	*skb = buffer->skb;
	buffer->skb = NULL;
	buffer_destroy(&key, buffer);
	spin_unlock_bh(&table_lock);

#ifdef BENCHMARK
	getnstimeofday(&skb_jcb(*skb_out)->start_time);
#endif

	return VER_CONTINUE;

lock_fail:
	spin_unlock_bh(&table_lock);
	return VER_DROP;
}

/**
 * Empties the database, freeing memory. Call during destruction to avoid memory leaks.
 */
void fragdb_destroy(void)
{
	del_timer_sync(&expire_timer);
	fragdb_table_empty(&table, buffer_dealloc);

	kmem_cache_destroy(buffer_cache);
	kfree(config);
}
