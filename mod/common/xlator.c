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
	 *
	 * This is only set if jool.fw matches FW_NETFILTER.
	 */
	struct nf_hook_ops *nf_ops;
#endif
};

static struct list_head __rcu *pool;
static DEFINE_MUTEX(lock);

static void destroy_jool_instance(struct jool_instance *instance)
{
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	if (instance->jool.fw & FW_NETFILTER)
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
 * Called whenever the user deletes a namespace. Supposed to deletes all the
 * instances inserted in that namespace.
 *
 * TODO (NOW) this might need some testing.
 * 1. Add instances to a namespace.
 * 2. Delete the namespace. Does it crash?
 *    -> If it doesn't crash, try unregistening the hooks during this function
 *       and try again. Does it crash?
 *    NOTE THAT destroy_jool_instance IS CALLED FROM GRAY CODE.
 * 3. Document the results.
 */
static void __net_exit flush_net(struct net *ns)
{
	struct list_head *list;
	struct jool_instance *instance, *tmp;
	LIST_HEAD(destroy_list);

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry_safe(instance, tmp, list, list_hook) {
		if (instance->jool.ns == ns) {
			list_del_rcu(&instance->list_hook);
			list_add(&instance->list_hook, &destroy_list);
		}
	}

	mutex_unlock(&lock);
	synchronize_rcu_bh();

	list_for_each_entry(instance, &destroy_list, list_hook)
		destroy_jool_instance(instance);
}

static struct pernet_operations joolns_ops = {
	.exit = flush_net,
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
int xlator_add(int fw, char *iname, struct xlator *result)
{
	struct list_head *list;
	struct jool_instance *instance;
	struct net *ns;
	int error;

	error = fw_validate(fw);
	if (error)
		return error;
	error = iname_validate(iname);
	if (error)
		return error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	/* All error roads from now need to put @ns. */

	instance = wkmalloc(struct jool_instance, GFP_KERNEL);
	if (!instance) {
		put_net(ns);
		return -ENOMEM;
	}

	/* All error roads from now need to free @instance. */

	strcpy(instance->jool.iname, iname);
	instance->jool.fw = fw;
	instance->jool.ns = ns; /* Transfers ownership */
	error = xlat_is_siit()
			? init_siit(&instance->jool)
			: init_nat64(&instance->jool);
	if (error) {
		wkfree(struct jool_instance, instance);
		put_net(ns);
		return error;
	}
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	instance->nf_ops = NULL;
#endif

	/* Error roads from now on don't need to put @ns. */
	/* Error roads from now on don't need to free @instance. */
	/* All error roads from now need to properly destroy @instance. */

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	if (fw & FW_NETFILTER) {
		struct nf_hook_ops *ops;

		ops = __wkmalloc("nf_hook_ops", 2 * sizeof(struct nf_hook_ops),
				GFP_KERNEL);
		if (!ops) {
			destroy_jool_instance(instance);
			return -ENOMEM;
		}

		init_nf_hook_op6(&instance->nf_ops[0]);
		init_nf_hook_op4(&instance->nf_ops[1]);

		/* TODO (NOW) WTF? Why is this not being reverted below? */
		error = nf_register_net_hooks(ns, ops, 2);
		if (error) {
			__wkfree("nf_hook_ops", ops);
			destroy_jool_instance(instance);
			return error;
		}

		instance->nf_ops = ops;
	}
#endif

	mutex_lock(&lock);
	error = xlator_find(ns, fw, iname, NULL);
	switch (error) {
	case 0:
		log_err("This namespace already has a Jool instance named '%s'.",
				iname);
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
 * Will actually delete the FIRST instance that matches [ns, fw, iname].
 * (Since fw is a bit flag, more than one instance can match.)
 * This is fine for now.
 */
static int __xlator_rm(struct net *ns, int fw, char *iname)
{
	struct list_head *list;
	struct jool_instance *instance;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry(instance, list, list_hook) {
		if (xlator_matches(&instance->jool, ns, fw, iname)) {
			list_del_rcu(&instance->list_hook);
			mutex_unlock(&lock);

			/* (The placement of this block doesn't matter much.) */
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
			if (instance->jool.fw & FW_NETFILTER)
				nf_unregister_net_hooks(ns, instance->nf_ops, 2);
#endif

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

/**
 * xlator_rm - Whenever called, stops translation of packets traveling through
 * the namespace running in the caller's context.
 */
int xlator_rm(int fw, char *iname)
{
	struct net *ns;
	int error;

	error = iname_validate(iname);
	if (error)
		return error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = __xlator_rm(ns, fw, iname);
	switch (error) {
	case 0:
		break;
	case -ESRCH:
		log_err("The requested instance does not exist.");
		break;
	default:
		log_err("Unknown error: %d.", error);
		break;
	}

	put_net(ns);
	return error;
}

static bool xlator_equals(struct xlator *x1, struct xlator *x2)
{
	return (x1->ns == x2->ns)
			&& (x1->fw == x2->fw)
			&& (strcmp(x1->iname, x2->iname) == 0);
}

int xlator_replace(struct xlator *jool)
{
	struct list_head *list;
	struct jool_instance *old;
	struct jool_instance *new;

	/* TODO (NOW) maybe validate iname & fw. */

	new = wkmalloc(struct jool_instance, GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	memcpy(&new->jool, jool, sizeof(*jool));
	xlator_get(&new->jool);

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry_rcu(old, list, list_hook) {
		if (xlator_equals(&old->jool, &new->jool)) {
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
 * A result value of 0 means success, -ESRCH means that this namespace has no
 * instance.
 * @result will be populated with the instance. Send NULL if you're not
 * interested.
 *
 * Please xlator_put() the instance when you're done using it.
 * IT IS EXTREMELY IMPORTANT THAT YOU NEVER KREF_GET ANY OF @result'S MEMBERS!!!
 * (You are not meant to fork pointers to them.)
 */
int xlator_find(struct net *ns, int fw, const char *iname,
		struct xlator *result)
{
	struct list_head *list;
	struct jool_instance *instance;
	int error;

	error = iname_validate(iname);
	if (error)
		return error;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_entry_rcu(instance, list, list_hook) {
		if (xlator_matches(&instance->jool, ns, fw, iname)) {
			if (result) {
				xlator_get(&instance->jool);
				memcpy(result, &instance->jool, sizeof(*result));
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
int xlator_find_current(int fw, const char *iname, struct xlator *result)
{
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_vnr(current)); /* +1 to ns. */
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	/* +1 to result's DBs, including ns. */
	error = xlator_find(ns, fw, iname, result);
	/* -1 to ns. */
	put_net(ns);
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

static bool offset_equals(struct instance_entry_usr *offset,
		struct jool_instance *instance)
{
	return (offset->ns == instance->jool.ns)
			&& (offset->fw == instance->jool.fw)
			&& (strcmp(offset->iname, instance->jool.iname) == 0);
}

int xlator_foreach(xlator_foreach_cb cb, void *args,
		struct instance_entry_usr *offset)
{
	struct list_head *list;
	struct jool_instance *instance;
	int error = 0;

	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_entry_rcu(instance, list, list_hook) {
		if (offset) {
			if (offset_equals(offset, instance))
				offset = NULL;
		} else {
			error = cb(&instance->jool, args);
			if (error)
				break;
		}
	}

	rcu_read_unlock_bh();

	if (error)
		return error;
	if (offset)
		return -ESRCH;
	return 0;
}

void xlator_copy_config(struct xlator *jool, struct full_config *copy)
{
	config_copy(&jool->global->cfg, &copy->global);
	bib_config_copy(jool->nat64.bib, &copy->bib);
	joold_config_copy(jool->nat64.joold, &copy->joold);
	fragdb_config_copy(jool->nat64.frag, &copy->frag);
}

bool xlator_matches(struct xlator *jool, struct net *ns, int fw,
		const char *iname)
{
	return (jool->ns == ns)
			&& (jool->fw & fw)
			&& (strcmp(jool->iname, iname) == 0);
}
