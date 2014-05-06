#include "nat64/mod/bib.h"

#include <net/ipv6.h>
#include "nat64/mod/pool4.h"
#include "nat64/mod/rbtree.h"
#include "nat64/mod/bib_db.h"
#include "nat64/mod/icmp_wrapper.h"


/********************************************
 * Structures and private variables.
 ********************************************/

/** Cache for struct bib_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

/*******************************
 * Private functions
 ******************************/

static void bib_release(struct kref *ref)
{
	struct bib_entry *bib = container_of(ref, struct bib_entry, refcounter);
	int error = 0;
	error = bibdb_remove(bib, bib->l4_proto);
	if (error) {
		log_crit(ERR_INCOMPLETE_REMOVE, "Error when trying to release the bib");
		return; /* should we delete(kfree) the BIB? at this point bibrefcount = 0 */
	}
	bib_kfree(bib);
}

/*******************************
 * Public functions.
 *******************************/

int bib_init(void)
{
	entry_cache = kmem_cache_create("jool_bib_entries", sizeof(struct bib_entry), 0, 0, NULL);
	if (!entry_cache) {
		log_err(ERR_ALLOC_FAILED, "Could not allocate the BIB entry cache.");
		return -ENOMEM;
	}

	return 0;
}

void bib_destroy(void)
{
	kmem_cache_destroy(entry_cache);
}

struct bib_entry *bib_create(struct ipv4_tuple_address *ipv4, struct ipv6_tuple_address *ipv6,
		bool is_static, l4_protocol l4_proto)
{
	struct bib_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	kref_init(&result->refcounter);
	result->ipv4 = *ipv4;
	result->ipv6 = *ipv6;
	result->l4_proto = l4_proto;
	result->is_static = is_static;
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);

	return result;
}
/**
 * we need to return the bib when we got one reference of this
 * by any function like bibdb_get or bibdb_get_by_ipvX
 */
int bib_return(struct bib_entry *bib)
{
	return kref_put(&bib->refcounter, bib_release);
}

/**
 * we need to add one reference to the counter when
 *  - is referenced by a session
 *  - iterated to the bib_tree_table, and get the reference
 *  - by any kind of container_of
 */
void bib_get(struct bib_entry *bib)
{
	kref_get(&bib->refcounter);
}

void bib_kfree(struct bib_entry *bib)
{
	pool4_return(bib->l4_proto, &bib->ipv4);
	kmem_cache_free(entry_cache, bib);
}

/**
 * Make sure you use bib_get or bibdb_get before you use
 * this function, otherwise could return a negative number
 * or an invalid number of sessions.
 */
int bib_session_counter(struct bib_entry *bib)
{
	int s = atomic_read(&bib->refcounter.refcount) - 1;
	if (bib->is_static)
		s--;

	return s;
}
