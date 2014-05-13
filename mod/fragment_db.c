#include "nat64/mod/fragment_db.h"
#include "nat64/comm/constants.h"
#include "nat64/mod/random.h"

#include <linux/version.h>

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
	/*
	 * I don't want this value to be a enum l4_protocol because I don't want people to be tempted
	 * to assign L4PROTO_NONE to it.
	 */
	__u8 l4_proto;
};

struct reassembly_buffer {
	/* The "hole descriptor list". */
	struct list_head holes;
	/* The "buffer". */
	struct packet *pkt;
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
static bool equals_function(struct reassembly_buffer_key *key1, struct reassembly_buffer_key *key2)
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
static unsigned int hash_function(struct reassembly_buffer_key *key)
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
static struct reassembly_buffer *buffer_alloc(struct fragment *frag)
{
	struct reassembly_buffer *buffer;
	struct packet *pkt;

	buffer = kmem_cache_alloc(buffer_cache, GFP_ATOMIC);
	if (!buffer)
		return NULL;
	if (is_error(pkt_create(frag, &pkt))) {
		kmem_cache_free(buffer_cache, buffer);
		return NULL;
	}

	INIT_LIST_HEAD(&buffer->holes);
	buffer->pkt = pkt;
	buffer->dying_time = jiffies + get_fragment_timeout();

	return buffer;
}

/**
 * Just a one-liner for populating reassembly_buffer_keys.
 */
static int frag_to_key(struct fragment *frag, struct reassembly_buffer_key *key)
{
	struct iphdr *hdr4;
	struct ipv6hdr *hdr6;
	struct hdr_iterator iterator;
	enum hdr_iterator_result result;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV4:
		hdr4 = frag_get_ipv4_hdr(frag);
		key->l3_proto = L3PROTO_IPV4;
		key->ipv4.src_addr.s_addr = hdr4->saddr;
		key->ipv4.dst_addr.s_addr = hdr4->daddr;
		key->ipv4.identification = hdr4->id;
		key->l4_proto = hdr4->protocol;
		break;

	case L3PROTO_IPV6:
		hdr6 = frag_get_ipv6_hdr(frag);
		key->l3_proto = L3PROTO_IPV6;
		key->ipv6.src_addr = hdr6->saddr;
		key->ipv6.dst_addr = hdr6->daddr;

		hdr_iterator_init(&iterator, hdr6);
		while (iterator.hdr_type != NEXTHDR_FRAGMENT) {
			result = hdr_iterator_next(&iterator);
			if (result != HDR_ITERATOR_SUCCESS)
				goto iterator_fail;
		}
		key->ipv6.identification = ((struct frag_hdr *) iterator.data)->identification;

		result = hdr_iterator_last(&iterator);
		if (result != HDR_ITERATOR_END)
			goto iterator_fail;
		key->l4_proto = iterator.hdr_type;
		break;
	}

	return 0;

iterator_fail:
	log_crit(ERR_INVALID_ITERATOR, "Iterator yielded status %u on a valid fragment.", result);
	return -EINVAL;
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

	pkt_kfree(buffer->pkt);
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
	/* Remove it from the DB. */
	if (!fragdb_table_remove(&table, key, NULL)) {
		log_crit(ERR_UNKNOWN_ERROR, "Something is attempting to delete a buffer that wasn't stored "
				"in the database.");
		return;
	}

	list_del(&buffer->list_hook);

	/* Deallocate it. */
	buffer_dealloc(buffer);
}

/**
 * One-liner to calculate the RFC's "fragment.first" value. The functionality is separated to make
 * the fragment_arrives() function a little less convoluted.
 */
static u16 compute_fragment_first(struct fragment *frag)
{
	u16 offset = 0; /* In bytes. */

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV4:
		offset = get_fragment_offset_ipv4(frag_get_ipv4_hdr(frag));
		break;
	case L3PROTO_IPV6:
		offset = get_fragment_offset_ipv6(frag_get_fragment_hdr(frag));
		break;
	}

	return offset >> 3;
}

/**
 * Returns "true" if "frag"'s MF flag is set. The point is to make the layer-3 protocol transparent
 * to the caller.
 */
static bool is_mf_set(struct fragment *frag)
{
	bool mf = false;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV4:
		mf = is_more_fragments_set_ipv4(frag_get_ipv4_hdr(frag));
		break;
	case L3PROTO_IPV6:
		mf = is_more_fragments_set_ipv6(frag_get_fragment_hdr(frag));
		break;
	}

	return mf;
}

/**
 * Core of the cleaner_timer() function, intended to actually clean the database from obsolete
 * fragments.
 */
static void clean_expired_buffers(void)
{
	struct list_head *current_hook, *next_hook;
	unsigned int b = 0;
	struct reassembly_buffer_key key;
	struct reassembly_buffer *buffer;

	/*
	 * Warning: Do *not* use buffer->pkt->first_fragment here.
	 * The fragment whose fragment offset is zero might still be in transit.
	 */

	log_debug("Deleting expired reassembly buffers...");

	spin_lock_bh(&table_lock);

	list_for_each_safe(current_hook, next_hook, &expire_list) {
		buffer = list_entry(current_hook, struct reassembly_buffer, list_hook);

		if (time_after(buffer->dying_time, jiffies)) {
			spin_unlock_bh(&table_lock);
			log_debug("Deleted %u reassembly buffers.", b);
			return;
		}

		if (!is_error(frag_to_key(pkt_get_first_frag(buffer->pkt), &key))) {
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
 * Assumes that "pkt" is UDP, and ensures the UDP header's checksum field is set.
 * This has to be done because the field is mandatory only in IPv6, so Jool has to make up for lazy
 * IPv4 nodes.
 *
 * This function assumes that pkt has no holes. That is, for each byte in the original packet,
 * there is at least one fragment in pkt that contains it.
 */
static int compute_csum_udp(struct packet *pkt)
{
	struct fragment *frag;
	struct iphdr *hdr4;
	struct udphdr *hdr_udp;
	unsigned char *buffer;
	unsigned int buffer_len;
	__u16 offset;
	int error;

	if (pkt_get_l3proto(pkt) == L3PROTO_IPV6)
		return 0; /* The checksum is mandatory in IPv6, so it's already set. */

	hdr_udp = frag_get_udp_hdr(pkt->first_fragment);
	if (hdr_udp->check != 0)
		return 0; /* The client went through the trouble of computing the csum. */

	/*
	 * Okay, compute the checksum.
	 * Implementation detail: We're going to assemble the fragments into a large buffer.
	 * Why? because some fragments might overlap with each other, so if we just join the checksums
	 * of each separate fragment, we'll end up summing some bytes multiple times.
	 *
	 * TODO (performance) OK fine, but at the very least we could avoid the copy when there is no
	 * fragmentation, since there is no overlapping and it's a pretty common scenario.
	 */
	error = pkt_get_total_len_ipv4(pkt, &buffer_len);
	if (error)
		return error;

	buffer = kmalloc(buffer_len, GFP_ATOMIC);
	if (!buffer)
		return -ENOMEM;

	list_for_each_entry(frag, &pkt->fragments, list_hook) {
		hdr4 = frag_get_ipv4_hdr(frag);
		offset = get_fragment_offset_ipv4(hdr4);
		memcpy(&buffer[offset], frag->l4_hdr.ptr, frag->l4_hdr.len);
		offset += frag->l4_hdr.len;
		memcpy(&buffer[offset], frag->payload.ptr, frag->payload.len);
	}

	hdr4 = frag_get_ipv4_hdr(pkt->first_fragment);
	hdr_udp->check = csum_tcpudp_magic(hdr4->saddr, hdr4->daddr, buffer_len, IPPROTO_UDP,
			csum_partial(buffer, buffer_len, 0));

	kfree(buffer);
	return 0;
}

/**
 * Assumes that pkt is a IPv6 ICMP message, and ensures that its checksum is valid, but only if it's
 * neccesary. See validate_csum_icmp4() for more info.
 */
static int validate_csum_icmp6(struct packet *pkt)
{
	struct fragment *frag;
	struct ipv6hdr *ip6_hdr;
	struct icmp6hdr *icmp6_hdr;
	__sum16 tmp;
	__sum16 computed_csum;

	frag = pkt->first_fragment;
	ip6_hdr = frag_get_ipv6_hdr(frag);
	icmp6_hdr = frag_get_icmp6_hdr(frag);
	if (!is_icmp6_error(icmp6_hdr->icmp6_type))
		return 0;

	tmp = icmp6_hdr->icmp6_cksum;
	icmp6_hdr->icmp6_cksum = 0;
	computed_csum = csum_ipv6_magic(&ip6_hdr->saddr, &ip6_hdr->daddr,
			frag->l4_hdr.len + frag->payload.len, NEXTHDR_ICMP,
			csum_partial(icmp6_hdr, frag->l4_hdr.len + frag->payload.len, 0));
	icmp6_hdr->icmp6_cksum = tmp;

	if (tmp != computed_csum) {
		log_warning("Checksum doesn't match. Expected: %x, actual: %x.", computed_csum, tmp);
		return -EINVAL;
	}

	return 0;
}

/**
 * Assumes that pkt is a IPv4 ICMP message, and ensures that its checksum is valid, but only if it's
 * neccesary. See the comments inside for more info.
 */
static int validate_csum_icmp4(struct packet *pkt)
{
	struct fragment *frag;
	struct icmphdr *hdr;
	__sum16 tmp;
	__sum16 computed_csum;

	frag = pkt->first_fragment;
	hdr = frag_get_icmp4_hdr(frag);
	if (!is_icmp4_error(hdr->type)) {
		/*
		 * The ICMP payload is not another packet.
		 * Hence, it will not be translated (it will be copied as-is).
		 * Hence, we will not have to recompute the checksum from scratch
		 * (we'll just update the old checksum with the new header's data).
		 * Hence, we don't have to validate the incoming checksum.
		 * (Because that will be the IPv6 node's responsibility.)
		 */
		return 0;
	}

	/* BTW: we're not iterating over all the fragments because ICMP errors are never fragmented. */
	tmp = hdr->checksum;
	hdr->checksum = 0;
	computed_csum = ip_compute_csum(hdr, frag->l4_hdr.len + frag->payload.len);
	hdr->checksum = tmp;

	if (tmp != computed_csum) {
		log_warning("Checksum doesn't match. Expected: %x, actual: %x.", computed_csum, tmp);
		return -EINVAL;
	}

	return 0;
}

/**
 * Cleans pkt's content of any leftover garbage. Currently, this means only adjusting transport
 * checksums.
 *
 * In an ideal world, Jool would not have to worry about checksums because it's really just a
 * pseudo-routing, mostly layer-3 device; layer-4 checksum verification is a task best left to
 * endpoints. However, in reality transport checksums are usually affected by the layer-3 protocol,
 * so we need to work around them.
 *
 * Thanks to this function, the rest of the modules after the fragment database can assume the
 * incoming layer-4 checksum is valid in all circumstances:
 * - If pkt is a TCP, ICMP info or a checksum-featuring UDP packet, this function does nothing
 *   because the translation mangling is going to be simple enough that Jool will be able to update
 *   (rather than recompute) the existing checksum. Any existing corruption will still be reflected
 *   in the checksum and the destination node will be able to tell.
 * - If pkt is a ICMP error, then this function will drop the packet if its checksum doesn't match.
 *   This is because the translation might change the packet considerably, so Jool will have to
 *   recompute the checksum completely, and we shouldn't assign a correct checksum to a corrupted
 *   packet.
 * - If pkt is a IPv4 zero-checksum UDP packet, then this function will compute and assign its
 *   checksum. If there's any corruption, the destination node will have to bear it. This behavior
 *   is mandated by RFC 6146 section 3.4.
 */
static int l4_post(struct packet *pkt) {
	int error = 0;

	switch (pkt_get_l4proto(pkt)) {
	case L4PROTO_TCP:
		/* Nothing to do here. */
		break;
	case L4PROTO_UDP:
		error = compute_csum_udp(pkt);
		break;

	case L4PROTO_ICMP:
		switch (pkt_get_l3proto(pkt)) {
		case L3PROTO_IPV4:
			error = validate_csum_icmp4(pkt);
			break;
		case L3PROTO_IPV6:
			error = validate_csum_icmp6(pkt);
			break;
		}
		break;

	case L4PROTO_NONE:
		log_warning("The transport protocol of the first fragment is NONE.");
		error = -EINVAL;
		break;
	}

	return error;
}

/**
 * Call during initialization for the remaining functions to work properly.
 */
int fragdb_init(void)
{
	int error;

	config = kmalloc(sizeof(*config), GFP_ATOMIC);

	if (!config) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate memory to store the fragmentation config.");
		return -ENOMEM;
	}
	config->fragment_timeout = msecs_to_jiffies(1000 * FRAGMENT_MIN);

	hole_cache = kmem_cache_create("jool_hole_descriptors", sizeof(struct hole_descriptor),
			0, 0, NULL);
	if (!hole_cache) {
		kfree(config);
		return -ENOMEM;
	}
	buffer_cache = kmem_cache_create("jool_reassembly_buffers", sizeof(struct reassembly_buffer),
			0, 0, NULL);
	if (!buffer_cache) {
		kmem_cache_destroy(hole_cache);
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
int clone_fragmentation_config(struct fragmentation_config *clone)
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
int set_fragmentation_config(__u32 operation, struct fragmentation_config *new_config)
{
	struct fragmentation_config *tmp_config;
	struct fragmentation_config *old_config;
	unsigned long fragment_min = msecs_to_jiffies(1000 * FRAGMENT_MIN);

	tmp_config = kmalloc(sizeof(*tmp_config), GFP_KERNEL);
	if (!tmp_config)
		return -ENOMEM;

	old_config = config;
	*tmp_config = *old_config;

	if (operation & FRAGMENT_TIMEOUT_MASK) {
		if (new_config->fragment_timeout < fragment_min) {
			log_err(ERR_FRAGMENTATION_TO_RANGE, "The fragment timeout must be at least %u seconds.",
					FRAGMENT_MIN);
			kfree(tmp_config);
			return -EINVAL;
		}

		tmp_config->fragment_timeout = new_config->fragment_timeout;
	}

	rcu_assign_pointer(config, tmp_config);
	synchronize_rcu_bh();
	kfree(old_config);

	return 0;
}

/**
 * Computes "skb"'s struct fragment, infers whether it is part of a larger packet, and stores it in
 * the database if it has siblings that haven't arrived yet. If they have all arrived, or if skb is
 * already whole, then it returns the resulting packet in "result".
 *
 * RFC 815, section 3.
 */
verdict fragment_arrives(struct sk_buff *skb, struct packet **result)
{
	/* The fragment collector skb belongs to. */
	struct reassembly_buffer *buffer;
	/* This is just a helper that allows us to quickly find buffer. */
	struct reassembly_buffer_key key;
	/* THE hole, repeatedly addressed by the RFC. */
	struct hole_descriptor *hole;
	/* Only helps to safely iterate. You generally needn't mind this one. */
	struct hole_descriptor *hole_aux;
	/* skb's descriptor. */
	struct fragment *frag;
	/* "fragment.first" as stated by the RFC. Spans 8 bytes. */
	u16 fragment_first = 0;
	/* "fragment.last" as stated by the RFC. Spans 8 bytes. */
	u16 fragment_last = 0;

	/*
	 * Encapsulating and validating the packet is not part of the RFC, we just do it because we
	 * need it. Just saying.
	 */
	if (is_error(frag_create_from_skb(skb, &frag)))
		return VER_DROP;

	/*
	 * This short circuit is not part of the RFC.
	 * I added it because I really don't want to spinlock nor allocate table stuff if I don't have
	 * to.
	 */
	if (!frag_is_fragmented(frag)) {
		/* No need to interact with the database. Encapsulate the packet and let it fly. */
		if (is_error(pkt_create(frag, result))) {
			frag_kfree(frag);
			return VER_STOLEN;
		}
		if (is_error(l4_post(*result))) {
			pkt_kfree(*result);
			return VER_STOLEN;
		}
		return VER_CONTINUE;
	}

	/*
	 * Store buffer's accesor so we don't have to recalculate it all the time.
	 * Also implementation specific, not part of the RFC.
	 */
	if (is_error(frag_to_key(frag, &key))) {
		frag_kfree(frag);
		return VER_DROP;
	}

	spin_lock_bh(&table_lock);

	/* Start reading page 4 here. "We start the algorithm when the earliest fragment..." */
	buffer = buffer_get(&key);
	if (buffer) {
		pkt_add_frag(buffer->pkt, frag);

	} else {
		buffer = buffer_alloc(frag);
		if (!buffer) {
			frag_kfree(frag);
			goto fail;
		}

		hole = hole_alloc(0, INFINITY);
		if (!hole) {
			kmem_cache_free(buffer_cache, buffer);
			frag_kfree(frag);
			goto fail;
		}

		list_add(&hole->list_hook, &buffer->holes);

		if (is_error(buffer_put(&key, buffer))) {
			kmem_cache_free(hole_cache, hole);
			kmem_cache_free(buffer_cache, buffer);
			frag_kfree(frag);
			goto fail;
		}
	}

	fragment_first = compute_fragment_first(frag);
	fragment_last = fragment_first + ((frag->l4_hdr.len + frag->payload.len - 8) >> 3);

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
		if (fragment_last < hole->last && is_mf_set(frag)) {
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
		*result = buffer->pkt;
		buffer->pkt = NULL;
		buffer_destroy(&key, buffer);
		spin_unlock_bh(&table_lock);

		if (is_error(l4_post(*result))) { /* omg fml =_= */
			pkt_kfree(*result);
			return VER_STOLEN;
		}

		return VER_CONTINUE;
	}

	/* RFC 815 ends here. */

	spin_unlock_bh(&table_lock);
	return VER_STOLEN;

fail:
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

	kmem_cache_destroy(hole_cache);
	kmem_cache_destroy(buffer_cache);
	kfree(config);
}
