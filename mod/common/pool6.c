#include "nat64/mod/common/pool6.h"
#include "nat64/common/constants.h"
#include "nat64/common/str_utils.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/tags.h"
#include "nat64/mod/common/types.h"

#include <linux/rculist.h>
#include <net/ipv6.h>


/**
 * A prefix within the pool.
 */
struct pool_entry {
	/** The address itself. */
	struct ipv6_prefix prefix;
	/** The thing that connects this object to the "pool" list. */
	struct list_head list_hook;
};

/**
 * The global container of the entire pool.
 * It can be a linked list because we're assuming we won't be holding too many prefixes.
 * The list contains nodes of type pool_entry.
 */
static struct list_head __rcu *pool;

static DEFINE_MUTEX(lock);

RCUTAG_FREE
static struct pool_entry *get_entry(struct list_head *node)
{
	return list_entry(node, struct pool_entry, list_hook);
}

RCUTAG_FREE
static int verify_prefix(int start, struct ipv6_prefix *prefix)
{
	int i;

	for (i = start; i < ARRAY_SIZE(prefix->address.s6_addr); i++) {
		if (prefix->address.s6_addr[i] & 0xFFU) {
			log_err("%pI6c/%u seems to have a suffix (RFC6052 doesn't like this).",
					&prefix->address, prefix->len);
			return -EINVAL;
		}
	}

	return 0;
}

RCUTAG_FREE
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

RCUTAG_USR /* Only because of GFP_KERNEL. Can be easily upgraded to FREE. */
static struct list_head *create_pool(void)
{
	struct list_head *result;

	result = kmalloc(sizeof(*result), GFP_KERNEL);
	if (!result)
		return NULL;
	INIT_LIST_HEAD(result);

	return result;
}

RCUTAG_USR
int pool6_init(char *pref_strs[], int pref_count)
{
	struct list_head *tmp;
	struct ipv6_prefix prefix;
	int i;
	int error;

	tmp = create_pool();
	if (!tmp)
		return -ENOMEM;

	mutex_lock(&lock);
	rcu_assign_pointer(pool, tmp);
	mutex_unlock(&lock);

	if (!pref_strs || pref_count == 0)
		return 0;

	for (i = 0; i < pref_count; i++) {
		error = prefix6_parse(pref_strs[i], &prefix);
		if (error)
			goto fail;
		error = pool6_add(&prefix);
		if (error)
			goto fail;
	}

	return 0;

fail:
	pool6_destroy();
	return error;
}

RCUTAG_USR
static void __replace(struct list_head *new)
{
	struct list_head *old_pool;
	struct list_head *node;
	struct list_head *tmp;

	mutex_lock(&lock);
	old_pool = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	rcu_assign_pointer(pool, new);
	mutex_unlock(&lock);

	synchronize_rcu_bh();

	list_for_each_safe(node, tmp, old_pool) {
		list_del(node);
		kfree(get_entry(node));
	}

	kfree(old_pool);
}

RCUTAG_USR
void pool6_destroy(void)
{
	__replace(NULL);
}

RCUTAG_USR
int pool6_flush(void)
{
	struct list_head *new;

	new = create_pool();
	if (!new)
		return -ENOMEM;

	__replace(new);
	return 0;
}

RCUTAG_PKT
int pool6_get(const struct in6_addr *addr, struct ipv6_prefix *result)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;

	if (WARN(!addr, "NULL is not a valid address."))
		return -EINVAL;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);

	if (list_empty(list)) {
		rcu_read_unlock_bh();
		log_warn_once("The IPv6 pool is empty.");
		return -ESRCH;
	}

	list_for_each_rcu_bh(node, list) {
		entry = get_entry(node);
		if (ipv6_prefix_equal(&entry->prefix.address, addr, entry->prefix.len)) {
			*result = entry->prefix;
			rcu_read_unlock_bh();
			return 0;
		}
	}

	rcu_read_unlock_bh();
	return -ESRCH;
}

RCUTAG_PKT
int pool6_peek(struct ipv6_prefix *result)
{
	struct list_head *list;
	struct pool_entry *entry;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);

	if (list_empty(list)) {
		rcu_read_unlock_bh();
		log_warn_once("The IPv6 pool is empty.");
		return -ESRCH;
	}

	/* Just return the first one. */
	entry = get_entry(rcu_dereference_bh(list_next_rcu(list)));
	*result = entry->prefix;

	rcu_read_unlock_bh();
	return 0;
}

RCUTAG_PKT
bool pool6_contains(struct in6_addr *addr)
{
	struct ipv6_prefix result;
	return !pool6_get(addr, &result); /* 0 -> true, -ESRCH or whatever -> false. */
}

int generic_add(struct ipv6_prefix *prefix, struct list_head *db)
{
	struct pool_entry *entry;
	int error;

	/* TODO can we remove this? */
	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	error = validate_prefix(prefix);
	if (error)
		return error; /* Error msg already printed. */

	if (xlat_is_siit() && !list_empty(db)) {
		log_err("SIIT Jool only supports one pool6 prefix at a time.");
		return -EINVAL;
	}

	list_for_each_entry(entry, db, list_hook) {
		if (prefix6_equals(&entry->prefix, prefix)) {
			log_err("The prefix already belongs to the pool.");
			return -EEXIST;
		}
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		log_err("Allocation of IPv6 pool node failed.");
		return -ENOMEM;
	}
	entry->prefix = *prefix;

	list_add_tail_rcu(&entry->list_hook, db);

	return 0;
}

/* TODO this is gonna need locking. */
int pool6_add(struct ipv6_prefix *prefix)
{
	log_debug("Inserting prefix to the IPv6 pool: %pI6c/%u.", &prefix->address, prefix->len);

	return generic_add(prefix,pool);
}

RCUTAG_USR
int pool6_remove(struct ipv6_prefix *prefix)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;

	/* TODO can we remove this? */
	if (WARN(!prefix, "NULL is not a valid prefix."))
		return -EINVAL;

	mutex_lock(&lock);
	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));

	list_for_each(node, list) {
		entry = get_entry(node);
		if (prefix6_equals(&entry->prefix, prefix)) {
			list_del_rcu(&entry->list_hook);
			mutex_unlock(&lock);
			synchronize_rcu_bh();
			kfree(entry);
			return 0;
		}
	}

	mutex_unlock(&lock);
	log_err("The prefix is not part of the pool.");
	return -ESRCH;
}

/**
 * pool6_for_each - run func() for every prefix in this pool.
 * @func: routine you want to run on every node in the pool.
 * @arg: additional argument that will be passed to func() on every iteration.
 * @offset: node you want to start iteration from. Iteration will start from
 *	the first node if you don't supply this.
 *
 * The nodes will be visited in the order in which they are stored.
 */
RCUTAG_PKT
int pool6_for_each(int (*func)(struct ipv6_prefix *, void *), void *arg,
		struct ipv6_prefix *offset)
{
	struct list_head *list;
	struct list_head *node;
	struct pool_entry *entry;
	int error = 0;

	rcu_read_lock_bh();
	list = rcu_dereference_bh(pool);

	list_for_each_rcu_bh(node, list) {
		entry = get_entry(node);
		if (!offset) {
			error = func(&entry->prefix, arg);
			if (error)
				break;
		} else if (prefix6_equals(offset, &entry->prefix)) {
			offset = NULL;
		}
	}

	rcu_read_unlock_bh();
	return offset ? -ESRCH : error;
}

RCUTAG_PKT
int pool6_count(__u64 *result)
{
	struct list_head *list;
	struct list_head *node;
	unsigned int count = 0;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_rcu_bh(node, list) {
		count++;
	}

	rcu_read_unlock_bh();

	*result = count;
	return 0;
}

RCUTAG_PKT
bool pool6_is_empty(void)
{
	bool result;
	rcu_read_lock_bh();
	result = list_empty(rcu_dereference_bh(pool));
	rcu_read_unlock_bh();
	return result;
}

static struct list_head *pool6_config_init_db(void)
{
	struct list_head *config_db = NULL;

	config_db = kmalloc(sizeof(*config_db), GFP_ATOMIC);
	if (!config_db) {
		log_err("Allocation of pool6 configuration database failed.");
		return NULL;
	}

	INIT_LIST_HEAD(config_db);

	return config_db;
}

static int pool6_config_add(struct list_head *db, struct ipv6_prefix *entry)
{
	return generic_add(entry, db);
}

static int pool6_switch_database(struct list_head *db)
{
	if (!db) {
		 log_err("Error while switching blacklist database, null pointer received.");
		 return 1;
	}

	pool6_destroy();
	pool = db;

	return 0;
}

int pool6_replace(struct ipv6_prefix *prefix) {
	struct list_head *config_db = pool6_config_init_db();

	if (!config_db) {
		return -ENOMEM;
	}

	if (pool6_config_add(config_db, prefix)) {
		log_err("An error occurred while trying to add the pool6 prefix to the config database!.") ;
		return 1;
	}

	if (pool6_switch_database(config_db)) {
		log_err("An error occurred while replacing the pool6 datbase with the config database!.") ;
		return 1;
	}

	return 0;
}
