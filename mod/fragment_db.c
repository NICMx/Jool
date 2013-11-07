#include "nat64/mod/fragment_db.h"
#include "nat64/comm/constants.h"


/**
 * @file
 * RFC 815, adapted to the requirement of only correlating (never assembling) fragments.
 */


#define INFINITY 1000

struct hole_descriptor {
	u16 first;
	u16 last;

	/** The thing that connects this object in its hole descriptor list. */
	struct list_head hook;
};

struct reassembly_buffer_key {
	__be32 src_addr;
	__be32 dst_addr;
	__u8 l4_proto;
	__be16 identification;
};

struct reassembly_buffer {
	/* The "hole descriptor list". */
	struct list_head holes;
	/* The "buffer". */
	struct packet *pkt;
	/* Jiffy at which the fragment timer will delete this buffer. */
	unsigned long dying_time;
};


#define HTABLE_NAME fragdb_table
#define KEY_TYPE struct reassembly_buffer_key
#define VALUE_TYPE struct reassembly_buffer
#include "hash_table.c"

static struct fragdb_table table;
static DEFINE_SPINLOCK(table_lock);

static struct fragmentation_config config;
static DEFINE_SPINLOCK(config_lock);


/* ----------------------------------------------------------------- */


static unsigned long get_fragment_timeout(void)
{
	unsigned long result;

	spin_lock_bh(&config_lock);
	result = config.fragment_timeout;
	spin_unlock_bh(&config_lock);

	return result;
}

static bool equals_function(struct reassembly_buffer_key *key1, struct reassembly_buffer_key *key2)
{
	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	return memcmp(key1, key2, sizeof(*key1)) == 0;
}

static __u16 hash_function(struct reassembly_buffer_key *key)
{
	return key->identification;
}

static bool skb_is_fragment(struct sk_buff *skb)
{
	struct iphdr *hdr = ip_hdr(skb);
	return get_fragment_offset_ipv4(hdr) == 0 && !is_more_fragments_set_ipv4(hdr);
}

static struct hole_descriptor *hole_alloc(u16 first, u16 last)
{
	struct hole_descriptor *hd = kmalloc(sizeof(*hd), GFP_ATOMIC);
	if (!hd)
		return NULL;

	hd->first = first;
	hd->last = last;
	/* hook can keep its trash. */

	return hd;
}

static struct packet *packet_from_skb(struct sk_buff *skb)
{
	struct packet *pkt;
	struct fragment *frag;

	frag = frag_create_ipv4(skb);
	if (!frag)
		return NULL;
	pkt = pkt_create_ipv4(frag);
	if (!pkt)
		kfree(frag);

	return pkt;
}

static struct reassembly_buffer *buffer_alloc(struct sk_buff *skb)
{
	struct reassembly_buffer *buffer;
	struct packet *pkt;

	buffer = kmalloc(sizeof(*buffer), GFP_ATOMIC);
	if (!buffer)
		return NULL;
	pkt = packet_from_skb(skb);
	if (!pkt) {
		kfree(buffer);
		return NULL;
	}

	INIT_LIST_HEAD(&buffer->holes);
	buffer->pkt = pkt;
	buffer->dying_time = jiffies + get_fragment_timeout();

	return buffer;
}

static void skb_to_key(struct sk_buff *skb, struct reassembly_buffer_key *key)
{
	struct iphdr *hdr = ip_hdr(skb);

	key->src_addr = hdr->saddr;
	key->dst_addr = hdr->daddr;
	key->l4_proto = hdr->protocol;
	key->identification = hdr->id;
}

static struct reassembly_buffer *buffer_get(struct sk_buff *skb)
{
	struct reassembly_buffer_key key;
	skb_to_key(skb, &key);
	return fragdb_table_get(&table, &key);
}

static void buffer_put(struct reassembly_buffer *buffer)
{
	struct reassembly_buffer_key key;
	skb_to_key(buffer->pkt->first_fragment->skb, &key);
	fragdb_table_put(&table, &key, buffer);
}

static void buffer_destroy(struct reassembly_buffer *buffer, bool free_pkt)
{
	struct reassembly_buffer_key key;

	/* Remove it from the DB. */
	skb_to_key(buffer->pkt->first_fragment->skb, &key);
	fragdb_table_remove(&table, &key, buffer);

	/* Deallocate it. */
	while (!list_empty(&buffer->holes)) {
		struct hole_descriptor *hole = list_entry(buffer->holes.next, struct hole_descriptor, hook);
		kfree(hole);
	}
	if (free_pkt)
		pkt_kfree(buffer->pkt, true);
	kfree(buffer);
}

int fragdb_init(void)
{
	config.fragment_timeout = msecs_to_jiffies(FRAGMENT_MIN);
	fragdb_table_init(&table, equals_function, hash_function);
	return 0;
}

/**
 * RFC 815, section 3.
 */
verdict fragment_arrives_ipv4(struct sk_buff *skb, struct packet **result)
{
	struct reassembly_buffer *buffer;
	struct hole_descriptor *hole;
	struct hole_descriptor *hole_aux;
	u16 fragment_first; /* In octets. */
	u16 fragment_last; /* In octets. */

	/*
	 * This short circuit is not part of the RFC.
	 * I added it because I really don't want to spinlock nor allocate if I don't have to.
	 */
	if (!skb_is_fragment(skb)) {
		*result = packet_from_skb(skb);
		return VER_CONTINUE;
	}

	spin_lock_bh(&table_lock);

	buffer = buffer_get(skb);
	if (!buffer) {
		buffer = buffer_alloc(skb);
		if (!buffer)
			goto fail;

		hole = hole_alloc(0, INFINITY);
		if (!hole) {
			kfree(buffer);
			goto fail;
		}

		list_add(&hole->hook, &buffer->holes);

		buffer_put(buffer);
	}

	fragment_first = ip_hdr(skb)->frag_off & IP_OFFSET;
	fragment_last = fragment_first + ((ip_hdr(skb)->tot_len - ip_hdrlen(skb)) >> 3);

	/* Step 1 */
	list_for_each_entry_safe(hole, hole_aux, &buffer->holes, hook) {
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
			if (!new_hole)
				goto fail;
			list_add(&new_hole->hook, hole->hook.prev);
		}

		/* Step 6 */
		if (fragment_last < hole->last && is_more_fragments_set_ipv4(ip_hdr(skb))) {
			struct hole_descriptor *new_hole;
			new_hole = hole_alloc(fragment_last + 1, hole->last);
			if (!new_hole)
				goto fail;
			list_add(&new_hole->hook, hole->hook.next);
		}

		/*
		 * Step 4
		 * (I had to move this because it seems to be the simplest way to append the new_holes to
		 * the list.)
		 */
		list_del(&hole->hook);
	} /* Step 7 */

	/* Step 8 */
	if (list_empty(&buffer->holes)) {
		*result = buffer->pkt;
		buffer_destroy(buffer, false);
		spin_unlock_bh(&table_lock);
		return VER_CONTINUE;
	}

	spin_unlock_bh(&table_lock);
	return VER_STOLEN;

fail:
	spin_unlock_bh(&table_lock);
	return VER_DROP;
}

void fragdb_destroy(void)
{
	fragdb_table_empty(&table, true);
}
