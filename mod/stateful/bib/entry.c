#include "nat64/mod/stateful/bib/entry.h"
#include "nat64/mod/common/config.h"
#include "nat64/common/str_utils.h"

/** Cache for struct bib_entrys, for efficient allocation. */
static struct kmem_cache *entry_cache;

int bibentry_init(void)
{
	entry_cache = kmem_cache_create("jool_bib_entries",
			sizeof(struct bib_entry), 0, 0, NULL);
	if (!entry_cache) {
		log_err("Could not allocate the BIB entry cache.");
		return -ENOMEM;
	}

	return 0;
}
void bibentry_destroy(void)
{
	kmem_cache_destroy(entry_cache);
}

/**
 * Allocates and initializes a BIB entry.
 * The entry is generated in dynamic memory; remember to kfree, return or pass it along.
 */
struct bib_entry *bibentry_create(const struct ipv4_transport_addr *addr4,
		const struct ipv6_transport_addr *addr6,
		const bool is_static, const l4_protocol proto)
{
	struct bib_entry tmp = {
			.ipv4 = *addr4,
			.ipv6 = *addr6,
			.l4_proto = proto,
			.is_static = is_static,
	};

	struct bib_entry *result = kmem_cache_alloc(entry_cache, GFP_ATOMIC);
	if (!result)
		return NULL;

	memcpy(result, &tmp, sizeof(tmp));
	kref_init(&result->refcounter);
	RB_CLEAR_NODE(&result->tree6_hook);
	RB_CLEAR_NODE(&result->tree4_hook);
	result->host4_addr = NULL;

	return result;
}

/**
 * Roughly reverts the work of bib_create() by freeing "bib" from memory. What breaks the symmetry
 * is the return of "bib"'s IPv4 address to the IPv4 pool (the borrow doesn't happen in
 * bib_create()).
 *
 * This is intended to be used when you are the only user of "bib" (i.e. you just created it
 * and you haven't inserted it to any tables). If that might not be the case, use bib_return()
 * instead.
 */
void bibentry_kfree(struct bib_entry *bib)
{
	kmem_cache_free(entry_cache, bib);
}

/**
 * Marks "bib" as being used by the caller. The idea is to prevent the cleaners from deleting it
 * while it's being used.
 *
 * You have to grab one of these references whenever you gain access to an entry. Keep in mind that
 * the bib* and bibdb* functions might have already done that for you. Session entries referencing
 * BIB entries must also count.
 *
 * Remove the mark when you're done by calling bib_return().
 */
void bibentry_get(struct bib_entry *bib)
{
	kref_get(&bib->refcounter);
}

/**
 * kref_put's function parameter cannot be NULL, so eh.
 */
static void shut_up(struct kref *ref)
{
	/* No code. */
}

/**
 * Substracts 1 reference from "bib"'s refcounter, and returns 1 if nobody is
 * referencing it anymore.
 * Only BIB's database module should call this function. Other modules should
 * call bibdb_return() (if "bib" belongs to the database) or bibentry_kfree()
 * (otherwise) instead.
 */
int bibentry_return(struct bib_entry *bib)
{
	/*
	 * I don't want to delete the entry in shut_up() because then this
	 * module would need to #include the BIB database module, and that would
	 * mean a circular dependency.
	 * This is the reason why only the DB module should call this function.
	 */
	return kref_put(&bib->refcounter, shut_up);
}

void bibentry_log(const struct bib_entry *bib, const char *action)
{
	struct timeval tval;
	struct tm t;

	if (!config_get_bib_logging())
		return;

	do_gettimeofday(&tval);
	time_to_tm(tval.tv_sec, 0, &t);
	log_info("%ld/%d/%d %d:%d:%d (GMT) - %s %pI6c#%u to %pI4#%u (%s)",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec, action,
			&bib->ipv6.l3, bib->ipv6.l4,
			&bib->ipv4.l3, bib->ipv4.l4,
			l4proto_to_string(bib->l4_proto));
}
