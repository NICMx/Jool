
/** Cache for struct bib_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

/**
 * Removes the BIB entry from the database and kfrees it.
 *
 * @param ref kref field of the entry you want to remove.
 */
static void bib_release(struct kref *ref, bool lock)
{
	struct bib_entry *bib;
	int error;

	bib = container_of(ref, struct bib_entry, refcounter);

	error = bibdb_remove(bib, lock);
	WARN(error, "Error code %d when trying to remove a dying BIB entry from the DB. "
			"Maybe it should have been kfreed directly instead?", error);
	bib_kfree(bib);
}

static void bib_release_lock(struct kref *ref)
{
	bib_release(ref, true);
}

static void bib_release_lockless(struct kref *ref)
{
	bib_release(ref, false);
}

/*******************************
 * Public functions.
 *******************************/

int bib_init(void)
{
	entry_cache = kmem_cache_create("jool_bib_entries", sizeof(struct bib_entry), 0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the BIB entry cache.");
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

void bib_kfree(struct bib_entry *bib)
{
	int error = pool4_return(bib->l4_proto, &bib->ipv4);
	WARN(error, "I'm a BIB entry and found error code %d while trying to return my IPv4 transport "
			"address to the IPv4 pool.", error);
	kmem_cache_free(entry_cache, bib);
}

void bib_get(struct bib_entry *bib)
{
	kref_get(&bib->refcounter);
}

int bib_return(struct bib_entry *bib)
{
	return kref_put(&bib->refcounter, bib_release_lock);
}

int bib_return_lockless(struct bib_entry *bib)
{
	return kref_put(&bib->refcounter, bib_release_lockless);
}
