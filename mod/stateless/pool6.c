#include "nat64/mod/stateless/pool6.h"
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/types.h"

#include <linux/inet.h>
#include <net/ipv6.h>


/**
 * The IPv6 global prefix container of the entire pool.
 */
static struct ipv6_prefix *pool6;

static int verify_prefix(int start, struct ipv6_prefix *prefix)
{
	int i;

	for (i = start; i < ARRAY_SIZE(prefix->address.s6_addr); i++) {
		if (prefix->address.s6_addr[i] & 0xFF) {
			log_err("%pI6c/%u seems to have a suffix (RFC6052 doesn't like this).",
					&prefix->address, prefix->len);
			return -EINVAL;
		}
	}

	return 0;
}

static int validate_prefix(struct ipv6_prefix *prefix)
{
	switch (prefix->len) {
	case 32:
		return verify_prefix(4, prefix);
	case 40:
		return verify_prefix(5, prefix);
	case 48:
		return verify_prefix(6, prefix);
	case 56:
		return verify_prefix(7, prefix);
	case 64:
		return verify_prefix(8, prefix);
	case 96:
		return verify_prefix(12, prefix);
	default:
		log_err("%u is not a valid prefix length (32, 40, 48, 56, 64, 96).", prefix->len);
		return -EINVAL;
	}
}

int pool6_init(char *pref_str)
{
	const char *slash_pos;

	pool6 = kmalloc(sizeof(struct ipv6_prefix), GFP_ATOMIC);
	if (!pool6) {
		log_err("Could not allocate the prefix 6 pool.");
		return -ENOMEM;
	}

	if (!pref_str) {
		pool6 = NULL;
		return 0;
	}

	if (in6_pton(pref_str, -1, (u8 *) &pool6->address.in6_u.u6_addr8, '/', &slash_pos) != 1)
		goto parse_failure;
	if (kstrtou8(slash_pos + 1, 0, &pool6->len) != 0)
		goto parse_failure;
	log_debug("Inserting prefix to the IPv6 pool: %pI6c/%u.", &pool6->address, pool6->len);
	return 0;

parse_failure:
	log_err("IPv6 prefix is malformed: %s.", pref_str);
	pool6_destroy();
	return -EINVAL;
}

void pool6_destroy(void)
{
	kfree(pool6);
}

int pool6_get(struct in6_addr *addr, struct ipv6_prefix *result)
{
	int error;
	struct ipv6_prefix tmp_pref;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	error = pool6_peek(&tmp_pref);
	if (error)
		return error;

	if (ipv6_prefix_equal(&tmp_pref.address, addr, tmp_pref.len)) {
		*result = tmp_pref;
		return 0;
	}

	return -ESRCH;
}

int pool6_peek(struct ipv6_prefix *result)
{
	struct ipv6_prefix *tmp;
	int error;

	rcu_read_lock_bh();
	tmp = rcu_dereference_bh(pool6);
	if (tmp) {
		*result = *tmp;
		error = 0;
	} else {
		error = -ESRCH;
	}
	rcu_read_unlock_bh();

	return error;
}

bool pool6_contains(struct in6_addr *addr)
{
	struct ipv6_prefix result;
	return !pool6_get(addr, &result); /* 0 -> true, -ENOENT or whatever -> false. */
}

/**
 * Remember this function must only be called with the configuration mutex locked.
 */
static int pool6_set(struct ipv6_prefix *new)
{
	struct ipv6_prefix *old_prefix = pool6;

	rcu_assign_pointer(pool6, new);
	synchronize_rcu_bh();

	if (old_prefix)
		kfree(old_prefix);

	return 0;
}

int pool6_add(struct ipv6_prefix *prefix)
{
	struct ipv6_prefix *new;
	int error;

	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	error = validate_prefix(prefix);
	if (error)
		return error; /* Error msg already printed. */

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	*new = *prefix;

	return pool6_set(new);
}

int pool6_count(__u64 *result)
{
	*result = pool6_is_empty() ? 0 : 1;
	return 0;
}

int pool6_for_each(int (*func)(struct ipv6_prefix *, void *), void * arg)
{
	int error;
	struct ipv6_prefix tmp;

	error = pool6_peek(&tmp);
	if (error)
		return error;

	return func(&tmp, arg);
}

int pool6_remove(struct ipv6_prefix *prefix)
{
	struct ipv6_prefix current_prefix;
	int error;

	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	error = pool6_peek(&current_prefix);
	if (error) {
		log_err("Pool6 is empty, nothing to be removed.");
		return error;
	}

	if (!prefix6_equals(&current_prefix, prefix)) {
		log_err("The prefix doesn't belong to the pool.");
		return -EINVAL;
	}

	return pool6_set(NULL);
}

int pool6_flush(void)
{
	return pool6_set(NULL);
}

bool pool6_is_empty(void)
{
	bool is_empty;

	rcu_read_lock_bh();
	is_empty = rcu_dereference_bh(pool6) ? false : true;
	rcu_read_unlock_bh();

	return is_empty;
}
