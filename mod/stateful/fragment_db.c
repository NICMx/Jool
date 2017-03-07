#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/common/constants.h"
#include "nat64/mod/common/config.h"
#include "nat64/mod/common/linux_version.h"
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
 * Used to prevent attackers from crafting special packets that will have the
 * same hash code but different hash slots. See
 * http://stackoverflow.com/questions/12175109
 */
static u32 rnd;

struct fragdb {
	struct fragdb_table table;

	struct list_head expire_list;
	/**
	 * Maximum number of jiffies any entry in this database should survive
	 * idle.
	 */
	unsigned long timeout;

	spinlock_t lock;
	struct kref ref;
};

/**
 * As specified above, the database is (mostly) a hash table. This is one of two
 * functions used internally by the table to search for values.
 */
static bool equals_function(const struct packet *k1, const struct packet *k2)
{
	struct ipv6hdr *hdr1;
	struct ipv6hdr *hdr2;

	if (k1 == k2)
		return true;
	if (k1 == NULL || k2 == NULL)
		return false;

	hdr1 = pkt_ip6_hdr(k1);
	hdr2 = pkt_ip6_hdr(k2);

	if (!addr6_equals(&hdr1->saddr, &hdr2->saddr))
		return false;
	if (!addr6_equals(&hdr1->daddr, &hdr2->daddr))
		return false;
	if (pkt_frag_hdr(k1)->identification != pkt_frag_hdr(k2)->identification)
		return false;
	if (pkt_l4_proto(k1) != pkt_l4_proto(k2))
		return false;

	return true;
}

#if LINUX_VERSION_AT_LEAST(3, 13, 0, 7, 2)
/**
 * Hash function for IPv6 keys from reassembly.c
 */
static unsigned int inet6_hash_frag(__be32 id, const struct in6_addr *saddr,
		const struct in6_addr *daddr, u32 rnd)
{
	u32 c;
	c = jhash_3words(ipv6_addr_hash(saddr), ipv6_addr_hash(daddr),
			(__force u32)id, rnd);
	return c & (INETFRAGS_HASHSZ - 1);
}
#endif

/**
 * As specified above, the database is a hash table. This is one of two
 * functions used internally by the table to search for values.
 */
static unsigned int hash_function(const struct packet *key)
{
	struct ipv6hdr *hdr = pkt_ip6_hdr(key);
	return inet6_hash_frag(pkt_frag_hdr(key)->identification,
			&hdr->saddr, &hdr->daddr, rnd);
}

int fragdb_init(void)
{
	buffer_cache = kmem_cache_create("jool_reassembly_buffers",
			sizeof(struct reassembly_buffer), 0, 0, NULL);
	if (!buffer_cache) {
		log_err("Could not allocate the reassembly buffer cache.");
		return -ENOMEM;
	}

	get_random_bytes(&rnd, sizeof(rnd));

	return 0;
}

void fragdb_destroy(void)
{
	kmem_cache_destroy(buffer_cache);
}

struct fragdb *fragdb_create(struct net *ns)
{
	struct fragdb *db;
	int error;

	db = wkmalloc(struct fragdb, GFP_KERNEL);
	if (!db)
		return NULL;

	error = fragdb_table_init(&db->table, equals_function, hash_function);
	if (error) {
		wkfree(struct fragdb, db);
		return NULL;
	}

	INIT_LIST_HEAD(&db->expire_list);
	db->timeout = msecs_to_jiffies(1000 * FRAGMENT_MIN);
	spin_lock_init(&db->lock);
	kref_init(&db->ref);

#ifndef UNIT_TESTING
#if LINUX_VERSION_AT_LEAST(4, 10, 0, 9999, 0)
	nf_defrag_ipv4_enable(ns);
	nf_defrag_ipv6_enable(ns);
#else
	nf_defrag_ipv4_enable();
	nf_defrag_ipv6_enable();
#endif
#endif

	return db;
}

void fragdb_get(struct fragdb *db)
{
	kref_get(&db->ref);
}

static void buffer_dealloc(struct reassembly_buffer *buffer)
{
	kfree_skb(buffer->pkt.skb);
	wkmem_cache_free("reassembly buffer", buffer_cache, buffer);
}

static void fragdb_release(struct kref *ref)
{
	struct fragdb *db;
	db = container_of(ref, struct fragdb, ref);
	fragdb_table_empty(&db->table, buffer_dealloc);
	wkfree(struct fragdb, db);
	/*
	 * Welp. There is no nf_defrag_ipv*_disable(). Guess we'll just have to
	 * leave those modules around.
	 */
}

void fragdb_put(struct fragdb *db)
{
	kref_put(&db->ref, fragdb_release);
}

void fragdb_config_copy(struct fragdb *db, struct fragdb_config *config)
{
	spin_lock_bh(&db->lock);
	config->ttl = db->timeout;
	spin_unlock_bh(&db->lock);
}

void fragdb_config_set(struct fragdb *db, struct fragdb_config *config)
{
	spin_lock_bh(&db->lock);
	db->timeout = config->ttl;
	spin_unlock_bh(&db->lock);
}

#define COMMON_MSG " Looks like nf_defrag_ipv6 is not sorting the fragments, " \
		"or something's shuffling them later. Please report."
static struct reassembly_buffer *add_pkt(struct fragdb *db, struct packet *pkt)
{
	struct reassembly_buffer *buffer;
	struct frag_hdr *hdr_frag = pkt_frag_hdr(pkt);
	unsigned int payload_len;

	/* Does it already exist? If so, add to and return existing buffer */
	buffer = fragdb_table_get(&db->table, pkt);
	if (buffer) {
		if (WARN(is_first_frag6(hdr_frag),
				"Non-first fragment's offset is zero."
				COMMON_MSG))
			return NULL;

		*buffer->next_slot = pkt->skb;
		buffer->next_slot = &pkt->skb->next;

		/*
		 * Why this? Dunno, both defrags do it when they support
		 * frag_list.
		 *
		 * Note, since we're in the middle of its sort of
		 * initialization, pkt is illegal at this point. It looks like
		 * we should call pkt_payload_len_frag() instead of
		 * pkt_payload_len_pkt(), but that's not the case because it
		 * represents a subsequent fragment. Be careful with the
		 * calculation of this length.
		 */
		payload_len = pkt_payload_len_pkt(pkt);
		buffer->pkt.skb->len += payload_len;
		buffer->pkt.skb->data_len += payload_len;
		buffer->pkt.skb->truesize += pkt->skb->truesize;
		skb_pull(pkt->skb, pkt_hdrs_len(pkt));

		return buffer;
	}

	if (WARN(!is_first_frag6(hdr_frag),
			"First fragment's offset is nonzero."
			COMMON_MSG))
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
	buffer = wkmem_cache_alloc("reassembly buffer", buffer_cache, GFP_ATOMIC);
	if (!buffer)
		return NULL;

	buffer->pkt = *pkt;
	buffer->pkt.original_pkt = &buffer->pkt;
	buffer->next_slot = &skb_shinfo(pkt->skb)->frag_list;
	buffer->dying_time = jiffies + db->timeout;

	if (fragdb_table_put(&db->table, pkt, buffer)) {
		wkmem_cache_free("reassembly buffer", buffer_cache, buffer);
		return NULL;
	}

	/* Schedule for automatic deletion */
	list_add_tail(&buffer->list_hook, &db->expire_list);

	return buffer;
}
#undef COMMON_MSG

/**
 * Removes "buffer" from the database and destroys it.
 */
static void buffer_destroy(struct fragdb *db, struct reassembly_buffer *buffer,
		struct packet *pkt)
{
	if (WARN(!fragdb_table_remove(&db->table, pkt, NULL),
			"Something is attempting to delete a buffer that wasn't stored in the database."))
		return;

	list_del(&buffer->list_hook);
	buffer_dealloc(buffer);
}

/**
 * Executed every once in a while to exterminate expired fragments.
 */
void fragdb_clean(struct fragdb *db)
{
	unsigned int b = 0;
	struct reassembly_buffer *buffer;

	spin_lock_bh(&db->lock);

	while (!list_empty(&db->expire_list)) {
		buffer = list_entry(db->expire_list.next,
				struct reassembly_buffer,
				list_hook);

		if (time_after(buffer->dying_time, jiffies)) {
			spin_unlock_bh(&db->lock);
			log_debug("Deleted %u reassembly buffers.", b);
			return;
		}

		buffer_destroy(db, buffer, &buffer->pkt);
		b++;
	}

	spin_unlock_bh(&db->lock);
}

#define COMMON_MSG " I will not be able to translate; aborting.\n" \
		"(I don't think this error is going to happen... but if it does, either some future kernel " \
		"version broke our assumptions or there is a kernel module in prerouting (pre-Jool), " \
		"which is doing some questionable edits on the packet.)"
/**
 * This whole module is a hack that tries to leverage nf_defrag_ipv6's hack,
 * but we can't do it if there are more hacks on top of it.
 * Therefore additional validations.
 */
static int validate_skb(struct sk_buff *skb)
{
	if (WARN(skb->prev || skb->next, "Packet is listed." COMMON_MSG))
		return -EINVAL;

	if (WARN(skb_shinfo(skb)->frag_list, "Packet has a fragment list."
			COMMON_MSG))
		return -EINVAL;

	return 0;
}
#undef COMMON_MSG

/**
 * Groups "skb_in" with the rest of its fragments.
 * If the rest of the fragments have not yet arrived, this will return
 * VER_STOLEN and store skb_in.
 * If all of the fragments have arrived, this will return VER_CONTINUE and the
 * zero-offset fragment will be returned in "skb_out". The rest of the fragments
 * can be accesed via skb_out's list (skb_shinfo(skb_out)->frag_list).
 */
verdict fragdb_handle(struct fragdb *db, struct packet *pkt)
{
	/* The fragment collector skb belongs to. */
	struct reassembly_buffer *buffer;
	struct frag_hdr *hdr_frag = pkt_frag_hdr(pkt);
	int error;

	if (!is_fragmented_ipv6(hdr_frag))
		return VERDICT_CONTINUE;

	/*
	 * Because the packet *is* fragmented, we know we're being compiled in
	 * kernel 3.12 or lower at this point.
	 * (Other defragmenters conceal the fragment header, effectively
	 * pretending there's no fragmentation.)
	 */
#if LINUX_VERSION_AT_LEAST(3, 13, 0, 7, 0)
	log_debug("This code is supposed to be unreachable in kernels 3.13+!");
	return VERDICT_DROP;
#endif

	log_debug("Adding fragment to database.");

	error = validate_skb(pkt->skb);
	if (error)
		return VERDICT_DROP;

	spin_lock_bh(&db->lock);

	buffer = add_pkt(db, pkt);
	if (!buffer) {
		spin_unlock_bh(&db->lock);
		return VERDICT_DROP;
	}

	/*
	 * nf_defrag_ipv6 is supposed to sort the fragments, so this condition
	 * should be all we need to figure out whether we have all the
	 * fragments.
	 * Otherwise we'd need to keep track of holes. If you ever find yourself
	 * needing to add hole logic, keep in mind that this module used to do
	 * that in Jool 3.2, so you might be able to reuse it.
	 */
	if (is_mf_set_ipv6(hdr_frag)) {
		spin_unlock_bh(&db->lock);
		return VERDICT_STOLEN;
	}

	*pkt = buffer->pkt;
	pkt->original_pkt = pkt;
	buffer->pkt.skb = NULL;
	/* Note, at this point, buffer->pkt is invalid. Do not use. */
	buffer_destroy(db, buffer, pkt);
	spin_unlock_bh(&db->lock);

	if (!skb_make_writable(pkt->skb, pkt_l3hdr_len(pkt)))
		return VERDICT_DROP;
	/* Why this? Dunno, both defrags do it when they support frag_list. */
	pkt_ip6_hdr(pkt)->payload_len = cpu_to_be16(pkt->skb->len
			- sizeof(struct ipv6hdr));
	/*
	 * The kernel's defrag also removes the fragment header.
	 * That actually harms us, so we don't mirror it. Instead, we make the
	 * fragment atomic.
	 * The rest of Jool must assume the packet might have a redundant
	 * fragment header.
	 */
	pkt_frag_hdr(pkt)->frag_off &= cpu_to_be16(~IP6_MF);

	log_debug("All the fragments are now available. Resuming translation...");
	return VERDICT_CONTINUE;
}
