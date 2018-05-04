#include "nat64/mod/common/xlator.h"

#include <linux/sched.h>
#include "nat64/common/types.h"
#include "nat64/common/xlat.h"
#include "nat64/mod/common/atomic_config.h"
#include "nat64/mod/common/linux_version.h"
#include "nat64/mod/common/nf_hook.h"
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
	 * @jool.ns holds anything reminiscent of an identifier...
	 */
	struct list_head list_hook;

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	/**
	 * This points to a 2-sized array for nf_register_net_hooks().
	 * The 2 is currently hardcoded in code below.
	 *
	 * It needs to be a pointer to an array and not an array because the
	 * ops needs to survive atomic configuration; the jool_instance needs to
	 * be replaced but the ops needs to survive.
	 */
	struct nf_hook_ops *nf_ops;
#endif
};

static struct list_head __rcu *pool;
static DEFINE_MUTEX(lock);

static void destroy_jool_instance(struct jool_instance *instance)
{
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	__wkfree("nf_hook_ops", instance->nf_ops);
#endif
	xlator_put(&instance->jool);
	wkfree(struct jool_instance, instance);
}

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
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
			nf_unregister_net_hooks(ns, instance->nf_ops, 2);
#endif

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
			destroy_jool_instance(instance);
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
 * xlator_setup - Initializes this module. Do not call other functions before
 * this one.
 */
int xlator_setup(void)
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
 * xlator_teardown - Graceful termination of this module. Reverts xlator_setup().
 * Will clean up any allocated memory.
 */
void xlator_teardown(void)
{
	unregister_pernet_subsys(&joolns_ops);
	__wkfree("xlator DB", rcu_dereference_raw(pool));
}

static int init_siit(struct xlator *jool)
{
	jool->global = config_alloc();
	if (!jool->global)
		goto config_fail;
	jool->pool6 = pool6_alloc();
	if (!jool->pool6)
		goto pool6_fail;
	jool->siit.eamt = eamt_alloc();
	if (!jool->siit.eamt)
		goto eamt_fail;
	jool->siit.blacklist = blacklist_alloc();
	if (!jool->siit.blacklist)
		goto blacklist_fail;
	jool->siit.pool6791 = rfc6791_alloc();
	if (!jool->siit.pool6791)
		goto rfc6791_fail;
	jool->newcfg = cfgcandidate_alloc();
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
	return -ENOMEM;
}

static int init_nat64(struct xlator *jool)
{
	jool->global = config_alloc();
	if (!jool->global)
		goto config_fail;
	jool->pool6 = pool6_alloc();
	if (!jool->pool6)
		goto pool6_fail;
	jool->nat64.frag = fragdb_alloc(jool->ns);
	if (!jool->nat64.frag)
		goto fragdb_fail;
	jool->nat64.pool4 = pool4db_alloc();
	if (!jool->nat64.pool4)
		goto pool4_fail;
	jool->nat64.bib = bib_alloc();
	if (!jool->nat64.bib)
		goto bib_fail;
	jool->nat64.joold = joold_alloc(jool->ns);
	if (!jool->nat64.joold)
		goto joold_fail;
	jool->newcfg = cfgcandidate_alloc();
	if (!jool->newcfg)
		goto newcfg_fail;

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
	return -ENOMEM;
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

	ns = get_net_ns_by_pid(task_pid_vnr(current));
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

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	instance->nf_ops = __wkmalloc("nf_hook_ops",
			2 * sizeof(struct nf_hook_ops),
			GFP_KERNEL);
	if (!instance->nf_ops) {
		destroy_jool_instance(instance);
		return -ENOMEM;
	}

	init_nf_hook_op6(&instance->nf_ops[0]);
	init_nf_hook_op4(&instance->nf_ops[1]);

	error = nf_register_net_hooks(ns, instance->nf_ops, 2);
	if (error) {
		destroy_jool_instance(instance);
		return error;
	}
#endif

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
	destroy_jool_instance(instance);
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

	ns = get_net_ns_by_pid(task_pid_vnr(current));
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
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
			new->nf_ops = old->nf_ops;
#endif
			list_replace_rcu(&old->list_hook, &new->list_hook);
			mutex_unlock(&lock);

			synchronize_rcu_bh();

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
			old->nf_ops = NULL;
#endif
			destroy_jool_instance(old);
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

	ns = get_net_ns_by_pid(task_pid_vnr(current)); /* +1 to ns. */
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
