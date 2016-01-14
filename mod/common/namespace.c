#include "nat64/mod/common/namespace.h"

#include <linux/sched.h>
#include "nat64/common/xlat.h"
#include "nat64/mod/common/types.h"
#include "nat64/mod/stateless/blacklist4.h"
#include "nat64/mod/stateless/rfc6791.h"

/**
 * All the configuration and state of the Jool instance in the given network
 * namespace (@ns).
 */
struct jool_instance {
	struct xlator jool;

	/*
	 * I want to turn this into a hash table, but it doesn't seem like
	 * @ns holds anything reminiscent of an identifier...
	 */
	struct list_head list_hook;
};

static struct list_head __rcu *pool;
static DEFINE_MUTEX(lock);

static void xlator_get(struct xlator *jool)
{
	get_net(jool->ns);

	config_get(jool->global);
	pool6_get(jool->pool6);

	if (xlat_is_siit()) {
		eamt_get(jool->siit.eamt);
		blacklist_get(jool->siit.blacklist);
		rfc6791_get(jool->siit.pool6791);
	} else {
//		pool4_get(jool->nat64.pool4);
//		bib_get(jool->nat64.bib);
//		session_get(jool->nat64.session);
	}
}

static void xlator_put(struct xlator *jool)
{
	if (jool->ns)
		put_net(jool->ns);

	if (jool->global)
		config_put(jool->global);
	if (jool->pool6)
		pool6_put(jool->pool6);

	if (xlat_is_siit()) {
		if (jool->siit.eamt)
			eamt_put(jool->siit.eamt);
		if (jool->siit.blacklist)
			blacklist_put(jool->siit.blacklist);
		if (jool->siit.pool6791)
			rfc6791_put(jool->siit.pool6791);
	} else {
//		if (jool->nat64.pool4)
//			pool4_put(jool->nat64.pool4);
//		if (jool->nat64.bib)
//			bib_put(jool->nat64.bib);
//		if (jool->nat64.session)
//			session_put(jool->nat64.session);
	}
}

/**
 * joolns_exit_net - stops translation of packets traveling through the @ns
 * namespace.
 */
static void __net_exit joolns_exit_net(struct net *ns)
{
	struct list_head *list;
	struct jool_instance *instance;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry(instance, list, list_hook) {
		if (instance->jool.ns == ns) {
			list_del_rcu(&instance->list_hook);
			mutex_unlock(&lock);
			xlator_put(&instance->jool);

			synchronize_rcu_bh();

			kfree(instance);
			return;
		}
	}

	mutex_unlock(&lock);
}

static struct pernet_operations joolns_ops = {
	.exit = joolns_exit_net,
};

/**
 * joolns_init - Initializes this module. Do not call other functions before
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
	RCU_INIT_POINTER(pool, list);

	error = register_pernet_subsys(&joolns_ops);
	if (error) {
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

	list = rcu_dereference_raw(pool);
	list_for_each_entry_safe(instance, tmp, list, list_hook) {
		joolns_put(&instance->jool);
		kfree(instance);
	}
	kfree(list);
}

static int init_siit(struct xlator *jool)
{
	int error;

	error = config_init(&jool->global, false);
	if (error)
		goto config_fail;
	error = pool6_init(&jool->pool6, NULL, 0);
	if (error)
		goto pool6_fail;
	error = eamt_init(&jool->siit.eamt);
	if (error)
		goto eamt_fail;
	error = blacklist_init(&jool->siit.blacklist, NULL, 0);
	if (error)
		goto blacklist_fail;
	error = rfc6791_init(&jool->siit.pool6791, NULL, 0);
	if (error)
		goto rfc6791_fail;

	return 0;

rfc6791_fail:
	blacklist_put(jool->siit.blacklist);
blacklist_fail:
	eamt_put(jool->siit.eamt);
eamt_fail:
	pool6_put(jool->pool6);
pool6_fail:
	config_put(jool->global);
config_fail:
	return error;
}

static int init_nat64(struct xlator *jool)
{
	int error;

	error = config_init(&jool->global, false);
	if (error)
		goto config_fail;
	error = pool6_init(&jool->pool6, NULL, 0);
//	if (error)
//		goto pool6_fail;
//	error = pool4_init(&jool->nat64.pool4);
//	if (error)
//		goto pool4_fail;
//	error = bibdb_init(&jool->nat64.bib);
//	if (error)
//		goto bibdb_fail;
//	error = sessiondb_init(&jool->nat64.session);
//	if (error)
//		goto sessiondb_fail;
//
//	return 0;
//
//sessiondb_fail:
//	bibdb_put(&jool->nat64.bib);
//bibdb_fail:
//	pool4_put(&jool->nat64.pool4);
//pool4_fail:
//	pool6_put(&jool->pool6);
//pool6_fail:
//	config_put(&jool->global);
config_fail:
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

	instance->jool.ns = ns;
	error = xlat_is_siit()
			? init_siit(&instance->jool)
			: init_nat64(&instance->jool);
	if (error) {
		put_net(ns);
		kfree(instance);
		return error;
	}

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

	put_net(ns);
	return 0;
}

/**
 * It is assumed @jool's krefs are transferred to the database.
 */
int joolns_replace(struct xlator *jool)
{
	struct list_head *list;
	struct jool_instance *old;
	struct jool_instance *new;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	memcpy(&new->jool, jool, sizeof(*jool));
	memset(jool, 0, sizeof(*jool));

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry_rcu(old, list, list_hook) {
		if (old->jool.ns == new->jool.ns) {
			list_replace_rcu(&old->list_hook, &new->list_hook);
			mutex_unlock(&lock);
			xlator_put(&old->jool);

			synchronize_rcu_bh();

			kfree(old);
			return 0;
		}
	}

	mutex_unlock(&lock);
	return -ESRCH;
}

/**
 * joolns_get - Retrieves the Jool instance currently loaded in namespace @ns.
 *
 * Please joolns_put() the instance when you're done using it.
 */
int joolns_get(struct net *ns, struct xlator *result)
{
	struct list_head *list;
	struct jool_instance *instance;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_entry_rcu(instance, list, list_hook) {
		if (instance->jool.ns == ns) {
			xlator_get(&instance->jool);
			memcpy(result, &instance->jool, sizeof(instance->jool));
			rcu_read_unlock_bh();
			return 0;
		}
	}

	rcu_read_unlock_bh();
	return -ESRCH;
}

/**
 * joolns_get - Retrieves the Jool instance loaded in the current namespace.
 *
 * Please joolns_put() the instance when you're done using it.
 */
int joolns_get_current(struct xlator *result)
{
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_nr(current)); /* +1 to ns. */
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = joolns_get(ns, result); /* +1 to result's DBs, including ns. */
	put_net(ns); /* -1 to ns. */
	return error;
}

void joolns_put(struct xlator *jool)
{
	xlator_put(jool);
}
