#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/common/types.h"

/**
 * @author Daniel Hdz Felix
 * @author Alberto Leiva
 */

#define ADDR6_BITS		128
#define ADDR4_BITS		32

#define INIT_KEY(ptr, length)	{ .bytes = (__u8 *)(ptr), .len = length }
#define ADDR_TO_KEY(addr)	INIT_KEY(addr, 8 * sizeof(*addr))
#define PREFIX_TO_KEY(prefix)	INIT_KEY(&(prefix)->address, (prefix)->len)

static DEFINE_MUTEX(lock);

static bool eamt_entry_equals(const struct eamt_entry *eam1,
		const struct eamt_entry *eam2)
{
	return prefix6_equals(&eam1->prefix6, &eam2->prefix6)
			&& prefix4_equals(&eam1->prefix4, &eam2->prefix4);
}

/**
 * validate_prefixes - check @prefix6 and @prefix4 can be joined together to
 * form a (standalone) legal EAM entry.
 */
static int validate_prefixes(struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	int error;

	error = prefix6_validate(prefix6);
	if (error)
		return error;

	error = prefix4_validate(prefix4);
	if (error)
		return error;

	if ((ADDR4_BITS - prefix4->len) > (ADDR6_BITS - prefix6->len)) {
		log_err("The IPv4 suffix length must be smaller or equal than the IPv6 suffix length.");
		return -EINVAL;
	}

	return 0;
}

static int validate_overlapping(struct eam_table *eamt,
		struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	struct eamt_entry old;
	struct rtrie_key key6 = PREFIX_TO_KEY(prefix6);
	struct rtrie_key key4 = PREFIX_TO_KEY(prefix4);
	int error;

	key6.len = 128;
	key4.len = 32;

	error = rtrie_get(&eamt->trie6, &key6, &old);
	if (!error) {
		/* TODO this should be log_. */
		log_err("Prefix %pI6c/%u overlaps with EAM [%pI6c/%u|%pI4/%u].\n"
				"(Use --force to override this validation.)",
				&prefix6->address, prefix6->len,
				&old.prefix6.address, old.prefix6.len,
				&old.prefix4.address, old.prefix4.len);
		return -EEXIST;
	}

	error = rtrie_get(&eamt->trie4, &key4, &old);
	if (!error) {
		pr_err("Prefix %pI4/%u overlaps with EAM [%pI6c/%u|%pI4/%u].\n"
				"(Use --force to override this validation.)",
				&prefix4->address, prefix4->len,
				&old.prefix6.address, old.prefix6.len,
				&old.prefix4.address, old.prefix4.len);
		return -EEXIST;
	}

	return 0;
}

static void __revert_add6(struct eam_table *eamt, struct ipv6_prefix *prefix6)
{
	struct rtrie_key key = PREFIX_TO_KEY(prefix6);
	int error;

	error = rtrie_rm(&eamt->trie6, &key);
	WARN(error, "Got error %d while trying to remove an EAM I just added.",
			error);
}

static int eamt_add6(struct eam_table *eamt, struct eamt_entry *eam)
{
	size_t addr_offset;
	int error;

	addr_offset = offsetof(typeof(*eam), prefix6.address);
	error = rtrie_add(&eamt->trie6, eam, addr_offset, eam->prefix6.len);
	if (error == -EEXIST) {
		log_err("Prefix %pI6c/%u already exists.",
				&eam->prefix6.address, eam->prefix6.len);
	}
	/* rtrie_print("IPv6 trie after add", &eamt.trie6); */

	return error;
}

static int eamt_add4(struct eam_table *eamt, struct eamt_entry *eam)
{
	size_t addr_offset;
	int error;

	addr_offset = offsetof(typeof(*eam), prefix4.address);
	error = rtrie_add(&eamt->trie4, eam, addr_offset, eam->prefix4.len);
	if (error == -EEXIST) {
		log_err("Prefix %pI4/%u already exists.",
				&eam->prefix4.address, eam->prefix4.len);
	}
	/* rtrie_print("IPv4 trie after add", &eamt.trie4); */

	return error;
}

int eamt_add(struct eam_table *eamt,
		struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4,
		bool force)
{
	struct eamt_entry new;
	int error;

	error = validate_prefixes(prefix6, prefix4);
	if (error)
		return error;

	mutex_lock(&lock);

	if (!force) {
		error = validate_overlapping(eamt, prefix6, prefix4);
		if (error)
			goto end;
	}

	new.prefix6 = *prefix6;
	new.prefix4 = *prefix4;

	error = eamt_add6(eamt, &new);
	if (error)
		goto end;
	error = eamt_add4(eamt, &new);
	if (error) {
		__revert_add6(eamt, prefix6);
		goto end;
	}

	eamt->count++;
end:
	mutex_unlock(&lock);
	return error;
}

static int get_exact6(struct eam_table *eamt, struct ipv6_prefix *prefix,
		struct eamt_entry *eam)
{
	struct rtrie_key key = PREFIX_TO_KEY(prefix);
	int error;

	error = rtrie_get(&eamt->trie6, &key, eam);
	if (error)
		return error;

	return (eam->prefix6.len == prefix->len) ? 0 : -ESRCH;
}

static int get_exact4(struct eam_table *eamt, struct ipv4_prefix *prefix,
		struct eamt_entry *eam)
{
	struct rtrie_key key = PREFIX_TO_KEY(prefix);
	int error;

	error = rtrie_get(&eamt->trie4, &key, eam);
	if (error)
		return error;

	return (eam->prefix4.len == prefix->len) ? 0 : -ESRCH;
}

static int __rm(struct eam_table *eamt,
		struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	struct rtrie_key key6 = PREFIX_TO_KEY(prefix6);
	struct rtrie_key key4 = PREFIX_TO_KEY(prefix4);
	int error;

	error = rtrie_rm(&eamt->trie6, &key6);
	if (error)
		goto corrupted;
	error = rtrie_rm(&eamt->trie4, &key4);
	if (error)
		goto corrupted;
	eamt->count--;

	/* rtrie_print("IPv6 trie after remove", &eamt.trie6); */
	/* rtrie_print("IPv4 trie after remove", &eamt.trie4); */
	return 0;

corrupted:
	WARN(true, "EAMT entry was extracted from the table, but it no longer seems to be there.\n"
			"Errcode: %d", error);
	return error;
}

static int eamt_rm_lockless(struct eam_table *eamt,
		struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	struct eamt_entry eam6;
	struct eamt_entry eam4;
	int error;

	if (!prefix4) {
		error = get_exact6(eamt, prefix6, &eam6);
		return error ? error : __rm(eamt, prefix6, &eam6.prefix4);
	}

	if (!prefix6) {
		error = get_exact4(eamt, prefix4, &eam4);
		return error ? error : __rm(eamt, &eam4.prefix6, prefix4);
	}

	error = get_exact6(eamt, prefix6, &eam6);
	if (error)
		return error;
	error = get_exact4(eamt, prefix4, &eam4);
	if (error)
		return error;

	return eamt_entry_equals(&eam6, &eam4)
			? __rm(eamt, prefix6, prefix4)
			: -ESRCH;
}

int eamt_rm(struct eam_table *eamt,
		struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	int error;

	if (WARN(!prefix6 && !prefix4, "Prefixes can't both be NULL"))
		return -EINVAL;

	mutex_lock(&lock);
	error = eamt_rm_lockless(eamt, prefix6, prefix4);
	mutex_unlock(&lock);

	return error;
}

bool eamt_contains6(struct eam_table *eamt, struct in6_addr *addr)
{
	struct rtrie_key key = ADDR_TO_KEY(addr);
	return rtrie_contains(&eamt->trie6, &key);
}

bool eamt_contains4(struct eam_table *eamt, __u32 addr)
{
	struct in_addr tmp = { .s_addr = addr };
	struct rtrie_key key = ADDR_TO_KEY(&tmp);
	return rtrie_contains(&eamt->trie4, &key);
}

int eamt_xlat_6to4(struct eam_table *eamt, struct in6_addr *addr6,
		struct in_addr *result)
{
	struct rtrie_key key = ADDR_TO_KEY(addr6);
	struct eamt_entry eam;
	unsigned int i;
	int error;

	/* Find the entry. */
	error = rtrie_get(&eamt->trie6, &key, &eam);
	if (error)
		return error;

	/* Translate the address. */
	for (i = 0; i < ADDR4_BITS - eam.prefix4.len; i++) {
		unsigned int offset4 = eam.prefix4.len + i;
		unsigned int offset6 = eam.prefix6.len + i;
		addr4_set_bit(&eam.prefix4.address, offset4,
				addr6_get_bit(addr6, offset6));
	}

	/* I'm assuming the prefix address is already zero-trimmed. */
	*result = eam.prefix4.address;
	return 0;
}

int eamt_xlat_4to6(struct eam_table *eamt, struct in_addr *addr4,
		struct in6_addr *result)
{
	struct rtrie_key key = ADDR_TO_KEY(addr4);
	struct eamt_entry eam;
	unsigned int i;
	int error;

	/* Find the entry. */
	error = rtrie_get(&eamt->trie4, &key, &eam);
	if (error)
		return error;

	/* Translate the address. */
	for (i = 0; i < ADDR4_BITS - eam.prefix4.len; i++) {
		unsigned int offset4 = eam.prefix4.len + i;
		unsigned int offset6 = eam.prefix6.len + i;
		addr6_set_bit(&eam.prefix6.address, offset6,
				addr4_get_bit(addr4, offset4));
	}

	/* I'm assuming the prefix address is already zero-trimmed. */
	*result = eam.prefix6.address;
	return 0;
}

int eamt_count(struct eam_table *eamt, __u64 *count)
{
	mutex_lock(&lock);
	*count = eamt->count;
	mutex_unlock(&lock);
	return 0;
}

bool eamt_is_empty(struct eam_table *eamt)
{
	return rtrie_is_empty(&eamt->trie6);
}

struct foreach_args {
	int (*cb)(struct eamt_entry *, void *);
	void *arg;
};

static int foreach_cb(void *eam, void *arg)
{
	struct foreach_args *args = arg;
	return args->cb(eam, args->arg);
}

int eamt_foreach(struct eam_table *eamt,
		int (*cb)(struct eamt_entry *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	struct foreach_args args = { .cb = cb, .arg = arg };
	struct rtrie_key offset_key;
	struct rtrie_key *offset_key_ptr = NULL;
	int error;

	args.cb = cb;
	args.arg = arg;

	if (offset) {
		offset_key.bytes = (__u8 *) &offset->address;
		offset_key.len = offset->len;
		offset_key_ptr = &offset_key;
	}

	mutex_lock(&lock);
	error = rtrie_foreach(&eamt->trie6, foreach_cb, &args, offset_key_ptr);
	mutex_unlock(&lock);
	return error;
}

void eamt_flush(struct eam_table *eamt)
{
	mutex_lock(&lock);
	rtrie_flush(&eamt->trie6);
	rtrie_flush(&eamt->trie4);
	eamt->count = 0;
	mutex_unlock(&lock);
}

int eamt_init(struct eam_table **eamt)
{
	struct eam_table *result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return -ENOMEM;

	rtrie_init(&result->trie6, sizeof(struct eamt_entry));
	rtrie_init(&result->trie4, sizeof(struct eamt_entry));
	result->count = 0;
	kref_init(&result->refcount);

	*eamt = result;
	return 0;
}

void eamt_get(struct eam_table *eamt)
{
	kref_get(&eamt->refcount);
}

static void destroy_eamt(struct kref *refcount)
{
	struct eam_table *eamt;
	eamt = container_of(refcount, typeof(*eamt), refcount);
	log_debug("Emptying EAMT...");
	rtrie_destroy(&eamt->trie6);
	rtrie_destroy(&eamt->trie4);
	kfree(eamt);
}

void eamt_put(struct eam_table *eamt)
{
	kref_put(&eamt->refcount, destroy_eamt);
}
