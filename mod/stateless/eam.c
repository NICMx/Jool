#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/common/rtrie.h"
#include "nat64/mod/common/types.h"

/**
 * @author Daniel Hdz Felix
 * @author Alberto Leiva
 */

#define ADDR6_BITS		128
#define ADDR4_BITS		32

#define INIT_KEY(ptr, length)	{ .bytes = (__u8 *) (ptr), .len = length }
#define ADDR_TO_KEY(addr)	INIT_KEY(addr, 8 * sizeof(*addr))
#define PREFIX_TO_KEY(prefix)	INIT_KEY(&(prefix)->address, (prefix)->len)

struct eam_table {
	struct rtrie trie6;
	struct rtrie trie4;
	/**
	 * This one isn't RCU-friendly. Touch only while you're holding the
	 * config spinlock.
	 */
	u64 count;
};

static struct eam_table eamt;

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
		log_err("The IPv4 suffix length must be smaller or equal than "
				"the IPv6 suffix length.");
		return -EINVAL;
	}

	return 0;
}

static int validate_overlapping(struct ipv6_prefix *prefix6,
		struct ipv4_prefix *prefix4)
{
	struct eamt_entry old;
	struct rtrie_key key6 = PREFIX_TO_KEY(prefix6);
	struct rtrie_key key4 = PREFIX_TO_KEY(prefix4);
	int error;

	key6.len = 128;
	key4.len = 32;

	error = rtrie_get(&eamt.trie6, &key6, &old);
	if (!error) {
		pr_err("Prefix %pI6c/%u overlaps with EAMT entry "
				"[%pI6c/%u|%pI4/%u]. ",
				&prefix6->address, prefix6->len,
				&old.prefix6.address, old.prefix6.len,
				&old.prefix4.address, old.prefix4.len);
		goto exists;
	}

	error = rtrie_get(&eamt.trie4, &key4, &old);
	if (!error) {
		pr_err("Prefix %pI4/%u overlaps with EAMT entry "
				"[%pI6c/%u|%pI4/%u]. ",
				&prefix4->address, prefix4->len,
				&old.prefix6.address, old.prefix6.len,
				&old.prefix4.address, old.prefix4.len);
		goto exists;
	}

	return 0;

exists:
	pr_cont("Use --force to override this validation.\n");
	return -EEXIST;
}

static void __revert_add6(struct ipv6_prefix *prefix6)
{
	struct rtrie_key key = PREFIX_TO_KEY(prefix6);
	int error;

	error = rtrie_rm(&eamt.trie6, &key);
	WARN(error, "Got error code %d while trying to remove an EAMT entry I "
			"just added.", error);
}

static int eamt_add6(struct eamt_entry *eam)
{
	int error;

	error = rtrie_add(&eamt.trie6, eam,
			offsetof(typeof(*eam), prefix6.address),
			eam->prefix6.len);
	if (error == -EEXIST) {
		log_err("Prefix %pI6c/%u already exists.",
				&eam->prefix6.address, eam->prefix6.len);
	}
	/* rtrie_print("IPv6 trie after add", &eamt.trie6); */

	return error;
}

static int eamt_add4(struct eamt_entry *eam)
{
	int error;

	error = rtrie_add(&eamt.trie4, eam,
			offsetof(typeof(*eam), prefix4.address),
			eam->prefix4.len);
	if (error == -EEXIST) {
		log_err("Prefix %pI4/%u already exists.",
				&eam->prefix4.address, eam->prefix4.len);
	}
	/* rtrie_print("IPv4 trie after add", &eamt.trie4); */

	return error;
}

int eamt_add(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4,
		bool force)
{
	struct eamt_entry new;
	int error;

	error = validate_prefixes(prefix6, prefix4);
	if (error)
		return error;

	if (!force) {
		error = validate_overlapping(prefix6, prefix4);
		if (error)
			return error;
	}

	new.prefix6 = *prefix6;
	new.prefix4 = *prefix4;

	error = eamt_add6(&new);
	if (error)
		return error;
	error = eamt_add4(&new);
	if (error) {
		__revert_add6(prefix6);
		return error;
	}

	eamt.count++;
	return 0;
}

static int get_exact6(struct ipv6_prefix *prefix, struct eamt_entry *eam)
{
	struct rtrie_key key = PREFIX_TO_KEY(prefix);
	int error;

	error = rtrie_get(&eamt.trie6, &key, eam);
	if (error)
		return error;

	return (eam->prefix6.len == prefix->len) ? 0 : -ESRCH;
}

static int get_exact4(struct ipv4_prefix *prefix, struct eamt_entry *eam)
{
	struct rtrie_key key = PREFIX_TO_KEY(prefix);
	int error;

	error = rtrie_get(&eamt.trie4, &key, eam);
	if (error)
		return error;

	return (eam->prefix4.len == prefix->len) ? 0 : -ESRCH;
}

static int __rm(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	struct rtrie_key key6 = PREFIX_TO_KEY(prefix6);
	struct rtrie_key key4 = PREFIX_TO_KEY(prefix4);
	int error;

	error = rtrie_rm(&eamt.trie6, &key6);
	if (error)
		goto corrupted;
	error = rtrie_rm(&eamt.trie4, &key4);
	if (error)
		goto corrupted;

	eamt.count--;
	/* rtrie_print("IPv6 trie after remove", &eamt.trie6); */
	/* rtrie_print("IPv4 trie after remove", &eamt.trie4); */
	return 0;

corrupted:
	WARN(true, "EAMT entry was extracted from the table, "
			"but it no longer seems to be there. "
			"Errcode: %d", error);
	return error;
}

int eamt_rm(struct ipv6_prefix *prefix6, struct ipv4_prefix *prefix4)
{
	struct eamt_entry eam6;
	struct eamt_entry eam4;
	int error;

	if (WARN(!prefix6 && !prefix4, "Prefixes can't both be NULL"))
		return -EINVAL;

	if (!prefix4) {
		error = get_exact6(prefix6, &eam6);
		return error ? error : __rm(prefix6, &eam6.prefix4);
	}

	if (!prefix6) {
		error = get_exact4(prefix4, &eam4);
		return error ? error : __rm(&eam4.prefix6, prefix4);
	}

	error = get_exact6(prefix6, &eam6);
	if (error)
		return error;
	error = get_exact4(prefix4, &eam4);
	if (error)
		return error;

	return eamt_entry_equals(&eam6, &eam4)
			? __rm(prefix6, prefix4)
			: -ESRCH;
}

bool eamt_contains6(struct in6_addr *addr)
{
	struct rtrie_key key = ADDR_TO_KEY(addr);
	return rtrie_contains(&eamt.trie6, &key);
}

bool eamt_contains4(__u32 addr)
{
	struct in_addr tmp = { .s_addr = addr };
	struct rtrie_key key = ADDR_TO_KEY(&tmp);
	return rtrie_contains(&eamt.trie4, &key);
}

int eamt_xlat_6to4(struct in6_addr *addr6, struct in_addr *result)
{
	struct rtrie_key key = ADDR_TO_KEY(addr6);
	struct eamt_entry eam;
	unsigned int i;
	int error;

	/* Find the entry. */
	error = rtrie_get(&eamt.trie6, &key, &eam);
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

int eamt_xlat_4to6(struct in_addr *addr4, struct in6_addr *result)
{
	struct rtrie_key key = ADDR_TO_KEY(addr4);
	struct eamt_entry eam;
	unsigned int i;
	int error;

	/* Find the entry. */
	error = rtrie_get(&eamt.trie4, &key, &eam);
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

int eamt_count(__u64 *count)
{
	*count = eamt.count;
	return 0;
}

bool eamt_is_empty(void)
{
	return rtrie_is_empty(&eamt.trie6);
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

int eamt_foreach(int (*cb)(struct eamt_entry *, void *), void *arg,
		struct ipv4_prefix *offset)
{
	struct foreach_args args = { .cb = cb, .arg = arg };
	struct rtrie_key offset_key;
	struct rtrie_key *offset_key_ptr = NULL;

	args.cb = cb;
	args.arg = arg;

	if (offset) {
		offset_key.bytes = (__u8 *) &offset->address;
		offset_key.len = offset->len;
		offset_key_ptr = &offset_key;
	}

	return rtrie_foreach(&eamt.trie6, foreach_cb, &args, offset_key_ptr);
}

void eamt_flush(void)
{
	rtrie_flush(&eamt.trie6);
	rtrie_flush(&eamt.trie4);
	eamt.count = 0;
}

int eamt_init(void)
{
	rtrie_init(&eamt.trie6, sizeof(struct eamt_entry));
	rtrie_init(&eamt.trie4, sizeof(struct eamt_entry));
	eamt.count = 0;
	return 0;
}

void eamt_destroy(void)
{
	log_debug("Emptying the Address Mapping table...");
	rtrie_destroy(&eamt.trie6);
	rtrie_destroy(&eamt.trie4);
}
