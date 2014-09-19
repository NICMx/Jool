#include "nat64/mod/fragment_db.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/stats.h"
#include "nat64/mod/packet.h"
#include "nat64/mod/random.h"

#include <linux/version.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

#define INFINITY 60000

struct hole_descriptor {
	u16 first;
	u16 last;

	/** The thing that connects this object in its hole descriptor list. */
	struct list_head list_hook;
};

/** Cache for struct hole_descriptors, for efficient allocation. */
static struct kmem_cache *hole_cache;

struct reassembly_buffer_key {
	l3_protocol l3_proto;
	union {
		struct {
			struct in_addr src_addr;
			struct in_addr dst_addr;
			__be16 identification;
		} ipv4;
		struct {
			struct in6_addr src_addr;
			struct in6_addr dst_addr;
			__be32 identification;
		} ipv6;
	};
	enum l4_protocol l4_proto;
};

struct reassembly_buffer {
	/* The "hole descriptor list". */
	struct list_head holes;
	/* The "buffer". */
	struct sk_buff *skb;
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

	if (key1->l3_proto != key2->l3_proto)
		return false;

	switch (key1->l3_proto) {
	case L3PROTO_IPV4:
		if (!ipv4_addr_equals(&key1->ipv4.src_addr, &key2->ipv4.src_addr))
			return false;
		if (!ipv4_addr_equals(&key1->ipv4.dst_addr, &key2->ipv4.dst_addr))
			return false;
		if (key1->ipv4.identification != key2->ipv4.identification)
			return false;
		break;
	case L3PROTO_IPV6:
		if (!ipv6_addr_equals(&key1->ipv6.src_addr, &key2->ipv6.src_addr))
			return false;
		if (!ipv6_addr_equals(&key1->ipv6.dst_addr, &key2->ipv6.dst_addr))
			return false;
		if (key1->ipv6.identification != key2->ipv6.identification)
			return false;
		break;
	}

	if (key1->l4_proto != key2->l4_proto)
		return false;

	return true;
}

/**
 * Hash function for IPv4 keys. Generally a blatant ripoff of ip_fragment.c's function of the same
 * name.
 */
static unsigned int ipqhashfn(__be16 id, __be32 saddr, __be32 daddr, u8 prot)
{
	return jhash_3words((__force u32)id << 16 | prot, (__force u32)saddr, (__force u32)daddr, rnd);
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
 * As specified above, the database is (mostly) a hash table. This is one of two functions used
 * internally by the table to search for values.
 */
static unsigned int hash_function(const struct reassembly_buffer_key *key)
{
	unsigned int result = 0;

	switch (key->l3_proto) {
	case L3PROTO_IPV4:
		result = ipqhashfn(key->ipv4.identification, key->ipv4.src_addr.s_addr,
				key->ipv4.dst_addr.s_addr, key->l4_proto);
		break;
	case L3PROTO_IPV6:
		result = inet6_hash_frag(key->ipv6.identification, &key->ipv6.src_addr,
				&key->ipv6.dst_addr, rnd);
		break;
	}

	return result;
}

/**
 * Just a one-liner for constructing hole_descriptors.
 */
static struct hole_descriptor *hole_alloc(u16 first, u16 last)
{
	struct hole_descriptor *hd = kmem_cache_alloc(hole_cache, GFP_ATOMIC);
	if (!hd)
		return NULL;

	hd->first = first;
	hd->last = last;
	/* hook can keep its trash. */

	return hd;
}

/**
 * Just a one-liner for constructing reassembly_buffers.
 */
static struct reassembly_buffer *buffer_alloc(struct sk_buff *skb)
{
	struct reassembly_buffer *buffer;

	buffer = kmem_cache_alloc(buffer_cache, GFP_ATOMIC);
	if (!buffer)
		return NULL;

	skb->next = skb->prev = skb;

	INIT_LIST_HEAD(&buffer->holes);
	buffer->skb = skb;
	buffer->dying_time = jiffies + get_fragment_timeout();

	return buffer;
}

/**
 * Just a one-liner for populating reassembly_buffer_keys.
 */
static int skb_to_key(struct sk_buff *skb, struct reassembly_buffer_key *key)
{
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;

	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV4:
		hdr4 = ip_hdr(skb);
		key->l3_proto = L3PROTO_IPV4;
		key->ipv4.src_addr.s_addr = hdr4->saddr;
		key->ipv4.dst_addr.s_addr = hdr4->daddr;
		key->ipv4.identification = hdr4->id;
		break;

	case L3PROTO_IPV6:
		hdr6 = ipv6_hdr(skb);
		key->l3_proto = L3PROTO_IPV6;
		key->ipv6.src_addr = hdr6->saddr;
		key->ipv6.dst_addr = hdr6->daddr;
		key->ipv6.identification = skb_frag_hdr(skb)->identification;
		break;
	}
	key->l4_proto = skb_l4_proto(skb);

	return 0;
}

/**
 * Returns the reassembly buffer described by "key" from the database.
 */
static struct reassembly_buffer *buffer_get(struct reassembly_buffer_key *key)
{
	return fragdb_table_get(&table, key);
}

/**
 * Inserts "buffer" into the database, mapping it to the descriptor "key".
 *
 * "key" is assumed to have been constructed from "buffer"; it is not inferred internally for silly
 * performance reasons.
 */
static int buffer_put(struct reassembly_buffer_key *key, struct reassembly_buffer *buffer)
{
	int error;

	error = fragdb_table_put(&table, key, buffer);
	if (error)
		return error;

	list_add(&buffer->list_hook, expire_list.prev);
	if (!timer_pending(&expire_timer) || time_before(buffer->dying_time, expire_timer.expires)) {
		mod_timer(&expire_timer, buffer->dying_time);
		log_debug("The buffer cleaning timer will awake in %u msecs.",
				jiffies_to_msecs(expire_timer.expires - jiffies));
	}

	return 0;
}

static void buffer_dealloc(struct reassembly_buffer *buffer)
{
	struct hole_descriptor *hole;

	while (!list_empty(&buffer->holes)) {
		hole = list_entry(buffer->holes.next, struct hole_descriptor, list_hook);
		list_del(&hole->list_hook);
		kmem_cache_free(hole_cache, hole);
	}

	if (buffer->skb) {
		/* kfree_skb_queued() assumes the list isn't circular, so uncircle it. */
		buffer->skb->prev->next = NULL;
		buffer->skb->prev = NULL;
		kfree_skb_queued(buffer->skb);
	}

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
 * One-liner to calculate the RFC's "fragment.first" value. The functionality is separated to make
 * the fragment_arrives() function a little less convoluted.
 */
static u16 compute_fragment_first(struct sk_buff *skb)
{
	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV4:
		return get_fragment_offset_ipv4(ip_hdr(skb)) >> 3;
	case L3PROTO_IPV6:
		return get_fragment_offset_ipv6(skb_frag_hdr(skb)) >> 3;
		break;
	}
	return 0;
}

/**
 * Returns "true" if "frag"'s MF flag is set. The point is to make the layer-3 protocol transparent
 * to the caller.
 */
static bool is_mf_set(struct sk_buff *skb)
{
	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV4:
		return is_more_fragments_set_ipv4(ip_hdr(skb));
	case L3PROTO_IPV6:
		return is_more_fragments_set_ipv6(skb_frag_hdr(skb));
	}
	return false;
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

	/*
	 * Warning: Do *not* use buffer->pkt->first_fragment here.
	 * The fragment whose fragment offset is zero might still be in transit.
	 */

	log_debug("Deleting expired reassembly buffers...");

	spin_lock_bh(&table_lock);

	while (!list_empty(&expire_list)) {
		buffer = list_entry(expire_list.next, struct reassembly_buffer, list_hook);

		if (time_after(buffer->dying_time, jiffies)) {
			spin_unlock_bh(&table_lock);
			log_debug("Deleted %u reassembly buffers.", b);
			return;
		}

		if (!is_error(skb_to_key(buffer->skb, &key))) {
			buffer_destroy(&key, buffer);
			b++;
		}
	}

	spin_unlock_bh(&table_lock);
	log_debug("Deleted %u reassembly buffers. The database is now empty.", b);
}

/**
 * Executed by the kernel every once in a while to extermine expired fragments.
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

	hole_cache = kmem_cache_create("jool_hole_descriptors", sizeof(struct hole_descriptor),
			0, 0, NULL);
	if (!hole_cache) {
		kfree(config);
		log_err("Could not allocate the hole descriptor cache.");
		return -ENOMEM;
	}
	buffer_cache = kmem_cache_create("jool_reassembly_buffers", sizeof(struct reassembly_buffer),
			0, 0, NULL);
	if (!buffer_cache) {
		kmem_cache_destroy(hole_cache);
		log_err("Could not allocate the reassembly buffer cache.");
		kfree(config);
		return -ENOMEM;
	}

	error = fragdb_table_init(&table, equals_function, hash_function);
	if (error) {
		kmem_cache_destroy(buffer_cache);
		kmem_cache_destroy(hole_cache);
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
int fragmentdb_clone_config(struct fragmentation_config *clone)
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
int fragmentdb_set_config(enum fragmentation_type type, size_t size, void *value)
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

/* TODO you don't have functions in types that do this? */
static bool skb_is_frag(struct sk_buff *skb)
{
	struct iphdr *hdr4;
	struct frag_hdr *hdr_frag;
	__u16 fragment_offset = 0;
	bool mf = false;

	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV4:
		hdr4 = ip_hdr(skb);
		fragment_offset = get_fragment_offset_ipv4(hdr4);
		mf = is_more_fragments_set_ipv4(hdr4);
		break;

	case L3PROTO_IPV6:
		hdr_frag = skb_frag_hdr(skb);
		if (!hdr_frag)
			return false;
		fragment_offset = get_fragment_offset_ipv6(hdr_frag);
		mf = is_more_fragments_set_ipv6(hdr_frag);
		break;
	}

	return (fragment_offset != 0) || (mf);
}

static bool is_first(struct sk_buff *skb)
{
	switch (skb_l3_proto(skb)) {
	case L3PROTO_IPV4:
		return is_first_fragment_ipv4(ip_hdr(skb));
	case L3PROTO_IPV6:
		return is_first_fragment_ipv6(skb_frag_hdr(skb));
	}
	return false;
}

static struct sk_buff *skb_add_frag(struct sk_buff *main, struct sk_buff *addend)
{
	if (is_first(addend)) {
		addend->prev = main->prev;
		addend->next = main;
		main->prev = addend;
		addend->prev->next = addend;
		return addend;
	}

	main->prev->next = addend;
	addend->prev = main->prev;
	addend->next = main;
	main->prev = addend;
	return main;
}

/**
 * Computes "skb"'s struct fragment, infers whether it is part of a larger packet, and stores it in
 * the database if it has siblings that haven't arrived yet. If they have all arrived, or if skb is
 * already whole, then it returns the resulting packet in "result".
 *
 * RFC 815, section 3.
 */
verdict fragment_arrives(struct sk_buff *skb_in, struct sk_buff **skb_out)
{
	/* The fragment collector skb belongs to. */
	struct reassembly_buffer *buffer;
	/* This is just a helper that allows us to quickly find buffer. */
	struct reassembly_buffer_key key;
	/* THE hole, repeatedly addressed by the RFC. */
	struct hole_descriptor *hole;
	/* Only helps to safely iterate. You generally needn't mind this one. */
	struct hole_descriptor *hole_aux;
	/* "fragment.first" as stated by the RFC. Spans 8 bytes. */
	u16 fragment_first = 0;
	/* "fragment.last" as stated by the RFC. Spans 8 bytes. */
	u16 fragment_last = 0;

	/*
	 * This short circuit is not part of the RFC.
	 * I added it because I really don't want to spinlock nor allocate table stuff if I don't have
	 * to.
	 */
	if (!skb_is_frag(skb_in)) {
		/* No need to interact with the database. Let the packet fly. */
		*skb_out = skb_in;
		return VER_CONTINUE;
	}

	inc_stats(skb_in, IPSTATS_MIB_REASMREQDS);

	/*
	 * Store buffer's accesor so we don't have to recalculate it all the time.
	 * Also implementation specific, not part of the RFC.
	 */
	if (is_error(skb_to_key(skb_in, &key))) {
		inc_stats(skb_in, IPSTATS_MIB_REASMFAILS);
		return VER_DROP;
	}

	spin_lock_bh(&table_lock);

	/* Start reading page 4 here. "We start the algorithm when the earliest fragment..." */
	buffer = buffer_get(&key);
	if (buffer) {
		buffer->skb = skb_add_frag(buffer->skb, skb_in);

	} else {
		buffer = buffer_alloc(skb_in);
		if (!buffer)
			goto fail;

		hole = hole_alloc(0, INFINITY);
		if (!hole) {
			kmem_cache_free(buffer_cache, buffer);
			goto fail;
		}

		list_add(&hole->list_hook, &buffer->holes);

		if (is_error(buffer_put(&key, buffer))) {
			kmem_cache_free(hole_cache, hole);
			kmem_cache_free(buffer_cache, buffer);
			goto fail;
		}
	}

	fragment_first = compute_fragment_first(skb_in);
	fragment_last = fragment_first + ((skb_l4hdr_len(skb_in) + skb_payload_len(skb_in) - 8) >> 3);

	/* Step 1 */
	list_for_each_entry_safe(hole, hole_aux, &buffer->holes, list_hook) {
		/* Step 2 */
		if (fragment_first > hole->last)
			continue;

		/* Step 3 */
		if (fragment_last < hole->first)
			continue;

		/* Step 5 */
		if (fragment_first > hole->first) {
			struct hole_descriptor *new_hole;
			new_hole = hole_alloc(hole->first, fragment_first - 1);
			if (!new_hole) {
				buffer_destroy(&key, buffer);
				goto fail;
			}
			list_add(&new_hole->list_hook, hole->list_hook.prev);
		}

		/* Step 6 */
		if (fragment_last < hole->last && is_mf_set(skb_in)) {
			struct hole_descriptor *new_hole;
			new_hole = hole_alloc(fragment_last + 1, hole->last);
			if (!new_hole) {
				buffer_destroy(&key, buffer);
				goto fail;
			}
			list_add(&new_hole->list_hook, &hole->list_hook);
		}

		/*
		 * Step 4
		 * (I had to move this because it seems to be the simplest way to append the new_holes to
		 * the list in steps 5 and 6.)
		 */
		list_del(&hole->list_hook);
		kmem_cache_free(hole_cache, hole);
	} /* Step 7 */

	/* Step 8 */
	if (list_empty(&buffer->holes)) {
		*skb_out = buffer->skb;
		buffer->skb = NULL;
		buffer_destroy(&key, buffer);
		spin_unlock_bh(&table_lock);

		(*skb_out)->prev->next = NULL;
		(*skb_out)->prev = NULL;

		inc_stats(*skb_out, IPSTATS_MIB_REASMOKS);
		return VER_CONTINUE;
	}

	/* RFC 815 ends here. */

	spin_unlock_bh(&table_lock);
	return VER_STOLEN;

fail:
	spin_unlock_bh(&table_lock);
	inc_stats(skb_in, IPSTATS_MIB_REASMFAILS);
	return VER_DROP;
}

/**
 * Empties the database, freeing memory. Call during destruction to avoid memory leaks.
 */
void fragdb_destroy(void)
{
	del_timer_sync(&expire_timer);
	fragdb_table_empty(&table, buffer_dealloc);

	kmem_cache_destroy(hole_cache);
	kmem_cache_destroy(buffer_cache);
	kfree(config);
}
