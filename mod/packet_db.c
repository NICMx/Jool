#include "nat64/mod/packet_db.h"
#include <net/ipv6.h>


struct pktdb_key {
	bool is_ipv6;
	union {
		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} ipv6;
		struct {
			struct in_addr src;
			struct in_addr dst;
		} ipv4;
	};
	u32 identifier;
};


#define HTABLE_NAME pktdb_table
#define KEY_TYPE struct pktdb_key
#define VALUE_TYPE struct packet
#include "hash_table.c"

static DEFINE_SPINLOCK(db_lock);
static struct pktdb_table table;
static LIST_HEAD(list);

static struct timer_list expire_timer;


static bool equals_function(struct pktdb_key *key1, struct pktdb_key *key2)
{
	if (key1 == key2)
		return true;
	if (key1 == NULL || key2 == NULL)
		return false;

	if (key1->identifier != key2->identifier)
		return false;
	if (key1->is_ipv6 != key2->is_ipv6)
		return false;

	if (key1->is_ipv6) {
		if (!ipv6_addr_equals(&key1->ipv6.src, &key2->ipv6.src))
			return false;
		if (!ipv6_addr_equals(&key1->ipv6.dst, &key2->ipv6.dst))
			return false;
	} else {
		if (!ipv4_addr_equals(&key1->ipv4.src, &key2->ipv4.src))
			return false;
		if (!ipv4_addr_equals(&key1->ipv4.dst, &key2->ipv4.dst))
			return false;
	}

	return true;
}

static __u16 hash_function(struct pktdb_key *key)
{
	return key->identifier;
}

static int frag_to_key(struct fragment *frag, struct pktdb_key *key)
{
	struct ipv6hdr *hdr6;
	struct iphdr *hdr4;
	struct frag_hdr *hdr_frag;

	switch (frag->l3_hdr.proto) {
	case L3PROTO_IPV6:
		hdr6 = frag_get_ipv6_hdr(frag);
		hdr_frag = frag_get_fragment_hdr(frag);
		if (!hdr_frag)
			return -EINVAL; /* Unfragmented packet */
		key->identifier = hdr_frag->identification;
		key->is_ipv6 = true;
		key->ipv6.src = hdr6->saddr;
		key->ipv6.dst = hdr6->daddr;
		break;

	case L3PROTO_IPV4:
		hdr4 = frag_get_ipv4_hdr(frag);
		key->is_ipv6 = false;
		key->ipv4.src.s_addr = hdr4->saddr;
		key->ipv4.dst.s_addr = hdr4->daddr;
		if ( !is_more_fragments_set_ipv4(hdr4)
			 && get_fragment_offset_ipv4(hdr4) == 0 )
			return -EINVAL; /* Unfragmented packet */
		key->identifier = be16_to_cpu(hdr4->id);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * pkt must NOT be a copy of the packet from the table.
 * (otherwise it will not be removed from the list correctly.)
 */
static bool pktdb_remove(struct packet *pkt)
{
	struct fragment *frag;
	struct pktdb_key key;

	frag = container_of(pkt->fragments.next, struct fragment, next);
	if (frag_to_key(frag, &key) != 0)
		return false;

	list_del(&pkt->pkt_list_node);
	return pktdb_table_remove(&table, &key, false);
}


static void clean_expired_fragments(void)
{
	struct list_head *current_node, *next_node;
	unsigned int f = 0;
	struct packet *pkt;

	log_debug("Deleting expired fragments...");

	spin_lock_bh(&db_lock);

	list_for_each_safe(current_node, next_node, &list) {
		pkt = list_entry(current_node, struct packet, pkt_list_node);

		if (time_after(pkt->dying_time, jiffies)) {
			spin_unlock_bh(&db_lock);
			log_debug("Deleted %u fragments.", f);
			return;
		}

		pktdb_remove(pkt);
		pkt_kfree(pkt, true);

		f++;
	}

	spin_unlock_bh(&db_lock);
	log_debug("Deleted %u fragments. The database is now empty.", f);
}

static void cleaner_timer(unsigned long param)
{
	struct packet *pkt;
	unsigned long next_expire;

	clean_expired_fragments();

	spin_lock_bh(&db_lock);
	if (list_empty(&list)) {
		spin_unlock_bh(&db_lock);
		/* No need to re-schedule the timer. */
		return;
	}

	/* Restart the timer. */
	pkt = list_entry(list.next, struct packet, pkt_list_node);
	next_expire = pkt->dying_time;
	spin_unlock_bh(&db_lock);
	mod_timer(&expire_timer, next_expire);
}

/*
 * Esto debe llamarse después de pkt_init().
 */
int pktdb_init(void)
{
	pktdb_table_init(&table, equals_function, hash_function);

	init_timer(&expire_timer);
	expire_timer.function = cleaner_timer;
	expire_timer.expires = 0;
	expire_timer.data = 0;

	return 0;
}

static struct packet *pktdb_get(struct fragment *frag)
{
	struct pktdb_key key;

	if (frag_to_key(frag, &key) != 0)
		return NULL;

	return pktdb_table_get(&table, &key);
}

static int pktdb_put(struct packet *pkt)
{
	struct fragment *frag;
	struct pktdb_key key;
	int error;

	frag = container_of(pkt->fragments.next, struct fragment, next);
	error = frag_to_key(frag, &key);
	if (error)
		return error;

	error = pktdb_table_put(&table, &key, pkt);
	if (error)
		return error;

	list_add(&pkt->pkt_list_node, list.prev);
	return 0;
}

verdict pkt_from_skb(struct sk_buff *skb, struct packet **pkt)
{
	struct packet *pkt_from_db;
	struct fragment *frag;
	verdict result;

	result = (skb->protocol == htons(ETH_P_IPV6))
			? frag_create_ipv6(skb, &frag)
			: frag_create_ipv4(skb, &frag);
	if (result != VER_CONTINUE)
		return result;

	spin_lock_bh(&db_lock);

	pkt_from_db = pktdb_get(frag);
	if (pkt_from_db) {
		if (skb->protocol == htons(ETH_P_IPV6))
			pkt_add_frag_ipv6(pkt_from_db, frag);
		else
			pkt_add_frag_ipv4(pkt_from_db, frag);

		if (pkt_is_complete(pkt_from_db)) {
			/* We're done collecting fragments. */
			pktdb_remove(pkt_from_db);
			INIT_LIST_HEAD(&pkt_from_db->pkt_list_node);
			*pkt = pkt_from_db;
			result = VER_CONTINUE;
		} else {
			/* Keep waiting for fragments. */
			result = VER_STOLEN;
		}

	} else {
		*pkt = (skb->protocol == htons(ETH_P_IPV6))
				? pkt_create_ipv6(frag)
				: pkt_create_ipv4(frag);

		if (pkt_is_complete(*pkt)) {
			/* No fragmentation; no need to reassemble. pkt is already set so just state success. */
			result = VER_CONTINUE;
		} else {
			/* skb is the first fragment we got. Store it and wait till the other ones arrive. */
			result = (pktdb_put(*pkt) == 0) ? VER_STOLEN : VER_DROP;
			if (!timer_pending(&expire_timer)) {
				log_debug("ESTOY ARRANCANDO EL TIMER.");
				mod_timer(&expire_timer, (*pkt)->dying_time);
			}
		}
	}

	spin_unlock_bh(&db_lock);
	return result;
}

void pktdb_destroy(void)
{
	pktdb_table_empty(&table, true);
	del_timer_sync(&expire_timer);
}
