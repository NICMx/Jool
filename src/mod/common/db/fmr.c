#include "mod/common/db/fmr.h"

#include "mod/common/log.h"
#include "mod/common/rtrie.h"
#include "mod/common/wkmalloc.h"

struct fmr_table {
	struct rtrie trie6;
	struct rtrie trie4;
	struct kref refcount;
};

static DEFINE_MUTEX(lock);

struct fmr_table *fmrt_alloc(void)
{
	struct fmr_table *result;

	result = wkmalloc(struct fmr_table, GFP_KERNEL);
	if (!result)
		return NULL;

	rtrie_init(&result->trie6, sizeof(struct mapping_rule), &lock);
	rtrie_init(&result->trie4, sizeof(struct mapping_rule), &lock);
	kref_init(&result->refcount);

	return result;
}

void fmrt_get(struct fmr_table *fmrt)
{
	kref_get(&fmrt->refcount);
}

/**
 * Please note: this function can sleep.
 */
static void fmrt_release(struct kref *refcount)
{
	struct fmr_table *fmrt;
	fmrt = container_of(refcount, struct fmr_table, refcount);
	rtrie_clean(&fmrt->trie6);
	rtrie_clean(&fmrt->trie4);
	wkfree(struct fmr_table, fmrt);
}

void fmrt_put(struct fmr_table *fmrt)
{
	kref_put(&fmrt->refcount, fmrt_release);
}

int fmrt_find4(struct fmr_table *fmrt, __be32 addr, struct mapping_rule *fmr)
{
	struct in_addr tmp = { .s_addr = addr };
	struct rtrie_key key = RTRIE_ADDR_TO_KEY(&tmp);
	return rtrie_find(&fmrt->trie4, &key, fmr);
}

int fmrt_find6(struct fmr_table *fmrt, struct in6_addr const *addr,
		struct mapping_rule *fmr)
{
	struct rtrie_key key = RTRIE_ADDR_TO_KEY(addr);
	return rtrie_find(&fmrt->trie6, &key, fmr);
}

static int fmrt_add6(struct fmr_table *fmrt, struct mapping_rule *fmr)
{
	size_t addr_offset;
	int error;

	addr_offset = offsetof(typeof(*fmr), prefix6.addr);
	error = rtrie_add(&fmrt->trie6, fmr, addr_offset, fmr->prefix6.len);
	if (error == -EEXIST) {
		log_err("Prefix %pI6c/%u already exists.", &fmr->prefix6.addr,
				fmr->prefix6.len);
	}

	return error;
}

static int fmrt_add4(struct fmr_table *fmrt, struct mapping_rule *fmr)
{
	size_t addr_offset;
	int error;

	addr_offset = offsetof(typeof(*fmr), prefix4.addr);
	error = rtrie_add(&fmrt->trie4, fmr, addr_offset, fmr->prefix4.len);
	if (error == -EEXIST) {
		log_err("Prefix %pI4/%u already exists.", &fmr->prefix4.addr,
				fmr->prefix4.len);
	}

	return error;
}

static void __revert_add6(struct fmr_table *fmrt, struct ipv6_prefix *prefix6)
{
	struct rtrie_key key = RTRIE_PREFIX_TO_KEY(prefix6);
	int error;

	error = rtrie_rm(&fmrt->trie6, &key);
	WARN(error, "Got error %d while trying to remove an FMR I just added.",
			error);
}

int fmrt_add(struct fmr_table *fmrt, struct mapping_rule *new)
{
	int error;

	/* TODO (MAP-T) This seems to be missing lots of validations */

	error = prefix6_validate(&new->prefix6);
	if (error)
		return error;
	error = prefix4_validate(&new->prefix4);
	if (error)
		return error;

	mutex_lock(&lock);

	error = fmrt_add6(fmrt, new);
	if (error)
		goto end;
	error = fmrt_add4(fmrt, new);
	if (error)
		__revert_add6(fmrt, &new->prefix6);

end:
	mutex_unlock(&lock);
	return error;
}
EXPORT_UNIT_SYMBOL(fmrt_add);

void fmrt_flush(struct fmr_table *fmrt)
{
	mutex_lock(&lock);
	rtrie_flush(&fmrt->trie6);
	rtrie_flush(&fmrt->trie4);
	mutex_unlock(&lock);
}

struct foreach_args {
	fmr_foreach_cb cb;
	void *arg;
};

static int foreach_cb(void const *fmr, void *arg)
{
	struct foreach_args *args = arg;
	return args->cb(fmr, args->arg);
}

int fmrt_foreach(struct fmr_table *fmrt,
		fmr_foreach_cb cb, void *arg,
		struct ipv4_prefix *offset)
{
	struct foreach_args args = { .cb = cb, .arg = arg };
	struct rtrie_key offset_key;
	struct rtrie_key *offset_key_ptr = NULL;
	int error;

	if (offset) {
		offset_key.bytes = (__u8 *) &offset->addr;
		offset_key.len = offset->len;
		offset_key_ptr = &offset_key;
	}

	mutex_lock(&lock);
	error = rtrie_foreach(&fmrt->trie4, foreach_cb, &args, offset_key_ptr);
	mutex_unlock(&lock);
	return error;
}
