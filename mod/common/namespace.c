#include "nat64/mod/common/namespace.h"
#include <linux/sched.h>
#include "nat64/common/xlat.h"
#include "nat64/mod/common/types.h"

static struct list_head __rcu *pool;
static DEFINE_MUTEX(lock);

/**
 * joolns_exit_net - stops translation of packets traveling through the @ns
 * namespace.
 */
static void /* __net_exit TODO uncomment */ joolns_exit_net(struct net *ns)
{
	struct list_head *list;
	struct jool_instance *instance;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry(instance, list, list_hook) {
		if (instance->ns == ns) {
			list_del_rcu(&instance->list_hook);
			joolns_put(instance);
			break;
		}
	}

	mutex_unlock(&lock);
}

static struct pernet_operations joolns_ops = {
	.exit = joolns_exit_net,
};

/**
 * joolns_exit_net - Initializes this module. Do not call other functions before
 * this one.
 */
int joolns_init(void)
{
	struct list_head *list;
	int error;

	list = kmalloc(sizeof(*list), GFP_KERNEL);
	if (!list)
		return -ENOMEM;
	INIT_LIST_HEAD(list);
	mutex_lock(&lock);
	rcu_assign_pointer(pool, list);
	mutex_unlock(&lock);

	error = register_pernet_subsys(&joolns_ops);
	if (error < 0) {
		kfree(list);
		return error;
	}

	return 0;
}

/**
 * joolns_destroy - Graceful termination of this module. Reverts joolns_init().
 * Will clean up any allocated memory.
 */
void joolns_destroy(void)
{
	struct list_head *list;
	struct jool_instance *instance;
	struct jool_instance *tmp;

	unregister_pernet_subsys(&joolns_ops);

	mutex_lock(&lock);
	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	rcu_assign_pointer(pool, NULL);
	mutex_unlock(&lock);

	list_for_each_entry_safe(instance, tmp, list, list_hook)
		joolns_put(instance);
	kfree(list);
}

static int init_siit(struct jool_instance *instance)
{
	int error;

//	error = config_init(instance->global);
//	if (error)
//		goto config_fail;
	error = pool6_init(/* instance->pool6, */ NULL, 0);
//	if (error)
//		goto pool6_fail;
//	error = eamt_init(instance->siit.eamt);
//	if (error)
//		goto eamt_fail;
//	error = blacklist_init(instance->siit.blacklist, NULL, 0);
//	if (error)
//		goto blacklist_fail;
//	error = rfc6791_init(instance->siit.pool6791, NULL, 0);
//	if (error)
//		goto rfc6791_fail;
//
//	return 0;
//
//rfc6791_fail:
//	blacklist_destroy(instance->siit.blacklist);
//blacklist_fail:
//	eamt_destroy(instance->siit.eamt);
//eamt_fail:
//	pool6_destroy(instance->pool6);
//pool6_fail:
//	config_destroy(instance->global);
//config_fail:
	return error;
}

static int init_nat64(struct jool_instance *instance)
{
	int error;

//	error = config_init(instance->global);
//	if (error)
//		goto config_fail;
	error = pool6_init(/* instance->pool6, */ NULL, 0);
//	if (error)
//		goto pool6_fail;
//	error = pool4_init(instance->nat64.pool4);
//	if (error)
//		goto pool4_fail;
//	error = bibdb_init(instance->nat64.bib);
//	if (error)
//		goto bibdb_fail;
//	error = sessiondb_init(instance->nat64.session);
//	if (error)
//		goto sessiondb_fail;
//
//	return 0;
//
//sessiondb_fail:
//	bibdb_destroy(instance->nat64.bib);
//bibdb_fail:
//	pool4_destroy(instance->nat64.pool4);
//pool4_fail:
//	pool6_destroy(instance->pool6);
//pool6_fail:
//	config_destroy(instance->global);
//config_fail:
	return error;
}

/**
 * joolns_add - Whenever called, starts translation of packets traveling through
 * the namespace running in the caller's context.
 */
int joolns_add(void)
{
	struct list_head *list;
	struct jool_instance *instance;
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_nr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	instance = kmalloc(sizeof(*instance), GFP_KERNEL);
	if (!instance) {
		put_net(ns);
		return -ENOMEM;
	}

	error = xlat_is_siit() ? init_siit(instance) : init_nat64(instance);
	if (error) {
		put_net(ns);
		kfree(instance);
		return error;
	}
	instance->ns = ns;
	kref_init(&instance->refcount);

	mutex_lock(&lock);
	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_add_tail_rcu(&instance->list_hook, list);
	mutex_unlock(&lock);

	return 0;
}

/**
 * joolns_rm - Whenever called, stops translation of packets traveling through
 * the namespace running in the caller's context.
 */
int joolns_rm(void)
{
	struct net *ns;

	ns = get_net_ns_by_pid(task_pid_nr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	joolns_exit_net(ns);
	return 0;
}

/**
 * joolns_get - Returns the translation databases associated with namespace @ns.
 *
 * Please joolns_put() the instance when you're done.
 */
struct jool_instance *joolns_get(struct net *ns)
{
	struct list_head *list;
	struct jool_instance *instance;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_entry_rcu(instance, list, list_hook) {
		if (instance->ns == ns) {
			kref_get(&instance->refcount);
			rcu_read_unlock_bh();
			return instance;
		}
	}

	rcu_read_unlock_bh();
	return NULL;
}

static void destroy_siit(struct jool_instance *instance)
{
//	rfc6791_destroy(instance->siit.pool6791);
//	blacklist_destroy(instance->siit.blacklist);
//	eamt_destroy(instance->siit.eamt);
	pool6_destroy(/* instance->pool6 */);
//	config_destroy(instance->global);
}

static void destroy_nat64(struct jool_instance *instance)
{
//	sessiondb_destroy(instance->nat64.session);
//	bibdb_destroy(instance->nat64.bib);
//	pool4_destroy(instance->nat64.pool4);
	pool6_destroy(/* instance->pool6 */);
//	config_destroy(instance->global);
}

static void release_instance(struct kref *kref)
{
	struct jool_instance *instance;
	instance = container_of(kref, typeof(*instance), refcount);

	put_net(instance->ns);
	if (xlat_is_siit())
		destroy_siit(instance);
	else
		destroy_nat64(instance);
	kfree(instance);
}

/**
 * Marks @instance as no longer being used by the caller. Will destroy it if
 * it lacks more referencers.
 */
void joolns_put(struct jool_instance *instance)
{
	kref_put(&instance->refcount, release_instance);
}
