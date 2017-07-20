#include "nat64/mod/common/xlator.h"

#include <linux/sched.h>
#include "nat64/common/types.h"
#include "nat64/common/xlat.h"
#include "nat64/mod/common/atomic_config.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateless/blacklist4.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/rfc6791.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/db.h"

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
		fragdb_get(jool->nat64.frag);
		pool4db_get(jool->nat64.pool4);
		bib_get(jool->nat64.bib);
		joold_get(jool->nat64.joold);
	}

	cfgcandidate_get(jool->newcfg);
}

/**
 * exit_net - stops translation of packets traveling through the @ns namespace.
 */
static int exit_net(struct net *ns)
{
	struct list_head *list;
	struct jool_instance *instance;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry(instance, list, list_hook) {
		if (instance->jool.ns == ns) {
			/* Remove the instance from the list FIRST. */
			list_del_rcu(&instance->list_hook);
			mutex_unlock(&lock);

			/* Then wait for the grace period. */
			synchronize_rcu_bh();

			/*
			 * Nobody can kref_get the databases now:
			 * Other code should not do it because of the
			 * xlator_find() contract, and xlator_find()'s
			 * xlator_get() already happened. Other xlator_find()'s
			 * xlator_get()s are not going to get in the way either
			 * because the instance is no longer listed.
			 * So finally return everything.
			 */
			xlator_put(&instance->jool);
			wkfree(struct jool_instance, instance);
			return 0;
		}
	}

	mutex_unlock(&lock);
	return -ESRCH;
}

static void __net_exit joolns_exit_net(struct net *ns)
{
	exit_net(ns);
}

static struct pernet_operations joolns_ops = {
	.exit = joolns_exit_net,
};

/**
 * xlator_init - Initializes this module. Do not call other functions before
 * this one.
 */
int xlator_init(void)
{
	struct list_head *list;
	int error;

	list = __wkmalloc("xlator DB", sizeof(struct list_head), GFP_KERNEL);
	if (!list)
		return -ENOMEM;
	INIT_LIST_HEAD(list);
	RCU_INIT_POINTER(pool, list);

	error = register_pernet_subsys(&joolns_ops);
	if (error) {
		__wkfree("xlator DB", list);
		return error;
	}

	return 0;
}

/**
 * xlator_destroy - Graceful termination of this module. Reverts xlator_init().
 * Will clean up any allocated memory.
 */
void xlator_destroy(void)
{
	struct list_head *list;
	struct jool_instance *instance;
	struct jool_instance *tmp;

	unregister_pernet_subsys(&joolns_ops);

	list = rcu_dereference_raw(pool);
	list_for_each_entry_safe(instance, tmp, list, list_hook) {
		xlator_put(&instance->jool);
		wkfree(struct jool_instance, instance);
	}
	__wkfree("xlator DB", list);
}

static int init_siit(struct xlator *jool)
{
	int error;

	error = config_init(&jool->global);
	if (error)
		goto config_fail;
	error = pool6_init(&jool->pool6);
	if (error)
		goto pool6_fail;
	error = eamt_init(&jool->siit.eamt);
	if (error)
		goto eamt_fail;
	error = blacklist_init(&jool->siit.blacklist);
	if (error)
		goto blacklist_fail;
	error = rfc6791_init(&jool->siit.pool6791);
	if (error)
		goto rfc6791_fail;
	jool->newcfg = cfgcandidate_create();
	if (!jool->newcfg)
		goto newcfg_fail;

	return 0;

newcfg_fail:
	rfc6791_put(jool->siit.pool6791);
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

	error = config_init(&jool->global);
	if (error)
		goto config_fail;
	error = pool6_init(&jool->pool6);
	if (error)
		goto pool6_fail;
	jool->nat64.frag = fragdb_create(jool->ns);
	if (!jool->nat64.frag) {
		error = -ENOMEM;
		goto fragdb_fail;
	}
	error = pool4db_init(&jool->nat64.pool4);
	if (error)
		goto pool4_fail;
	jool->nat64.bib = bib_create();
	if (!jool->nat64.bib) {
		error = -ENOMEM;
		goto bib_fail;
	}
	jool->nat64.joold = joold_create(jool->ns);
	if (!jool->nat64.joold) {
		error = -ENOMEM;
		goto joold_fail;
	}

	jool->newcfg = cfgcandidate_create();
	if (!jool->newcfg) {
		error = -ENOMEM;
		goto newcfg_fail;
	}

	return 0;

newcfg_fail:
	joold_put(jool->nat64.joold);
joold_fail:
	bib_put(jool->nat64.bib);
bib_fail:
	pool4db_put(jool->nat64.pool4);
pool4_fail:
	fragdb_put(jool->nat64.frag);
fragdb_fail:
	pool6_put(jool->pool6);
pool6_fail:
	config_put(jool->global);
config_fail:
	return error;
}

/**
 * xlator_add - Whenever called, starts translation of packets traveling through
 * the namespace running in the caller's context.
 * @result: Will be initialized with a reference to the new translator. Send
 *     NULL if you're not interested.
 */
int xlator_add(struct xlator *result)
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

	instance = wkmalloc(struct jool_instance, GFP_KERNEL);
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
		wkfree(struct jool_instance, instance);
		return error;
	}

	mutex_lock(&lock);
	error = xlator_find(ns, NULL);
	switch (error) {
	case 0:
		log_err("This namespace already has a Jool instance.");
		error = -EEXIST;
		goto mutex_fail;
	case -ESRCH: /* Happy path. */
		break;
	default:
		log_err("Unknown error code: %d.", error);
		goto mutex_fail;
	}

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_add_tail_rcu(&instance->list_hook, list);

	if (result) {
		xlator_get(&instance->jool);
		memcpy(result, &instance->jool, sizeof(instance->jool));
	}

	mutex_unlock(&lock);
	return 0;

mutex_fail:
	mutex_unlock(&lock);
	xlator_put(&instance->jool);
	wkfree(struct jool_instance, instance);
	return error;
}

/**
 * xlator_rm - Whenever called, stops translation of packets traveling through
 * the namespace running in the caller's context.
 */
int xlator_rm(void)
{
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_nr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = exit_net(ns);
	switch (error) {
	case 0:
		break;
	case -ESRCH:
		log_err("This namespace doesn't have a Jool instance.");
		break;
	default:
		log_err("Unknown error code: %d.", error);
		break;
	}

	put_net(ns);
	return error;
}

int xlator_replace(struct xlator *jool)
{
	struct list_head *list;
	struct jool_instance *old;
	struct jool_instance *new;

	new = wkmalloc(struct jool_instance, GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	memcpy(&new->jool, jool, sizeof(*jool));
	xlator_get(&new->jool);

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry_rcu(old, list, list_hook) {
		if (old->jool.ns == new->jool.ns) {
			/* The comments at exit_net() also apply here. */
			list_replace_rcu(&old->list_hook, &new->list_hook);
			mutex_unlock(&lock);

			synchronize_rcu_bh();

			xlator_put(&old->jool);
			wkfree(struct jool_instance, old);
			return 0;
		}
	}

	mutex_unlock(&lock);
	return -ESRCH;
}

/**
 * xlator_find - Retrieves the Jool instance currently loaded in namespace @ns.
 *
 * Please xlator_put() the instance when you're done using it.
 * IT IS EXTREMELY IMPORTANT THAT YOU NEVER KREF_GET ANY OF @result'S MEMBERS!!!
 * (You are not meant to fork pointers to them.)
 *
 * If @result is NULL, it's because the namespace has no instance.
 */
int xlator_find(struct net *ns, struct xlator *result)
{
	struct list_head *list;
	struct jool_instance *instance;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_entry_rcu(instance, list, list_hook) {
		if (instance->jool.ns == ns) {
			if (result) {
				xlator_get(&instance->jool);
				memcpy(result, &instance->jool,
						sizeof(instance->jool));
			}
			rcu_read_unlock_bh();
			return 0;
		}
	}

	rcu_read_unlock_bh();
	return -ESRCH;
}

/**
 * xlator_find_current - Retrieves the Jool instance loaded in the current
 * namespace.
 *
 * Please xlator_put() the instance when you're done using it.
 */
int xlator_find_current(struct xlator *result)
{
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_nr(current)); /* +1 to ns. */
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = xlator_find(ns, result); /* +1 to result's DBs, including ns. */
	put_net(ns); /* -1 to ns. */
	return error;
}

/*
 * I am kref_put()ting and there's no lock.
 * This can be dangerous: http://lwn.net/Articles/93617/
 *
 * I believe this is safe because this module behaves as as a "home" for all
 * these objects. While this module is dropping its reference, the refcounter
 * is guaranteed to be at least 1. Nobody can get a new reference while or after
 * this happens. Therefore nobody can sneak in a kref_get during the final put.
 */
void xlator_put(struct xlator *jool)
{
	put_net(jool->ns);

	config_put(jool->global);
	pool6_put(jool->pool6);

	if (xlat_is_siit()) {
		eamt_put(jool->siit.eamt);
		blacklist_put(jool->siit.blacklist);
		rfc6791_put(jool->siit.pool6791);
	} else {
		fragdb_put(jool->nat64.frag);
		pool4db_put(jool->nat64.pool4);
		bib_put(jool->nat64.bib);
		joold_put(jool->nat64.joold);
	}

	cfgcandidate_put(jool->newcfg);
}

int xlator_foreach(xlator_foreach_cb cb, void *args)
{
	struct list_head *list;
	struct jool_instance *instance;
	int error = 0;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_entry_rcu(instance, list, list_hook) {
		error = cb(&instance->jool, args);
		if (error)
			break;
	}

	rcu_read_unlock_bh();
	return error;
}

void xlator_copy_config(struct xlator *jool, struct full_config *copy)
{
	config_copy(&jool->global->cfg, &copy->global);
	bib_config_copy(jool->nat64.bib, &copy->bib);
	joold_config_copy(jool->nat64.joold, &copy->joold);
	fragdb_config_copy(jool->nat64.frag, &copy->frag);
}
