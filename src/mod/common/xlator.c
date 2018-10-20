#include "mod/common/xlator.h"

#include <linux/sched.h>

#include "common/types.h"
#include "common/xlat.h"
#include "mod/common/atomic_config.h"
#include "mod/common/defrag.h"
#include "mod/common/kernel_hook.h"
#include "mod/common/linux_version.h"
#include "mod/common/wkmalloc.h"
#include "mod/siit/blacklist4.h"
#include "mod/siit/eam.h"
#include "mod/nat64/joold.h"
#include "mod/nat64/pool4/db.h"
#include "mod/nat64/bib/db.h"

/**
 * All the configuration and state of the Jool instance in the given network
 * namespace (@ns).
 */
struct jool_instance {
	/* TODO (later) maybe turn this into a const. */
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

static void destroy_jool_instance(struct jool_instance *instance, bool unhook)
{
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	if (instance->jool.fw & FW_NETFILTER) {
		if (unhook) {
			nf_unregister_net_hooks(instance->jool.ns,
					instance->nf_ops, 2);
		}
		__wkfree("nf_hook_ops", instance->nf_ops);
	}
#endif

	xlator_put(&instance->jool);
	log_info("Deleting instance '%s'.", instance->jool.iname);
	wkfree(struct jool_instance, instance);
}

static void xlator_get(struct xlator *jool)
{
	jstat_get(jool->stats);
	config_get(jool->global);

	if (xlat_is_siit()) {
		eamt_get(jool->siit.eamt);
		blacklist_get(jool->siit.blacklist);
	} else {
		pool4db_get(jool->nat64.pool4);
		bib_get(jool->nat64.bib);
		joold_get(jool->nat64.joold);
	}
}

static void __flush_detach(struct net *ns, struct list_head *detached)
{
	struct list_head *list;
	struct jool_instance *instance, *tmp;

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry_safe(instance, tmp, list, list_hook) {
		if (instance->jool.ns == ns) {
			list_del_rcu(&instance->list_hook);
			list_add(&instance->list_hook, detached);
		}
	}
}

static void __flush_delete(struct list_head *detached)
{
	struct jool_instance *instance, *tmp;

	if (list_empty(detached))
		return; /* Calling synchronize_rcu_bh() for no reason is bad. */

	synchronize_rcu_bh();

	list_for_each_entry_safe(instance, tmp, detached, list_hook)
		destroy_jool_instance(instance, true);
}

/**
 * Called whenever the user deletes a namespace. Supposed to delete all the
 * instances inserted in that namespace.
 */
static void flush_net(struct net *ns)
{
	LIST_HEAD(detached);

	mutex_lock(&lock);
	__flush_detach(ns, &detached);
	mutex_unlock(&lock);

	__flush_delete(&detached);
}

/**
 * Called whenever the user deletes... several namespaces? I'm not really sure.
 * The idea seems to be to minimize the net amount of synchronize_rcu_bh()
 * calls, but the kernel seems to always call flush_net() first and
 * flush_batch() next. It seems self-defeating to me.
 *
 * Maybe delete flush_net(); I guess it's redundant.
 */
static void flush_batch(struct list_head *net_exit_list)
{
	struct net *ns;
	LIST_HEAD(detached);

	mutex_lock(&lock);
	list_for_each_entry(ns, net_exit_list, exit_list)
		__flush_detach(ns, &detached);
	mutex_unlock(&lock);

	__flush_delete(&detached);
}

static struct pernet_operations joolns_ops = {
	.exit = flush_net,
	.exit_batch = flush_batch,
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
	if (error)
		__wkfree("xlator DB", list);
	return error;
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

static int init_siit(struct xlator *jool, struct config_prefix6 *pool6)
{
	jool->stats = jstat_alloc();
	if (!jool->stats)
		goto stats_fail;
	jool->global = config_alloc(pool6);
	if (!jool->global)
		goto config_fail;
	jool->siit.eamt = eamt_alloc();
	if (!jool->siit.eamt)
		goto eamt_fail;
	jool->siit.blacklist = blacklist_alloc();
	if (!jool->siit.blacklist)
		goto blacklist_fail;

	return 0;

blacklist_fail:
	eamt_put(jool->siit.eamt);
eamt_fail:
	config_put(jool->global);
config_fail:
	jstat_put(jool->stats);
stats_fail:
	return -ENOMEM;
}

static int init_nat64(struct xlator *jool, struct config_prefix6 *pool6)
{
	jool->stats = jstat_alloc();
	if (!jool->stats)
		goto stats_fail;
	jool->global = config_alloc(pool6);
	if (!jool->global)
		goto config_fail;
	jool->nat64.pool4 = pool4db_alloc();
	if (!jool->nat64.pool4)
		goto pool4_fail;
	jool->nat64.bib = bib_alloc();
	if (!jool->nat64.bib)
		goto bib_fail;
	jool->nat64.joold = joold_alloc(jool->ns);
	if (!jool->nat64.joold)
		goto joold_fail;

	return 0;

joold_fail:
	bib_put(jool->nat64.bib);
bib_fail:
	pool4db_put(jool->nat64.pool4);
pool4_fail:
	config_put(jool->global);
config_fail:
	jstat_put(jool->stats);
stats_fail:
	return -ENOMEM;
}

/**
 * This only inits the databases for now.
 * ns, fw and iname are the caller's responsibility.
 */
int xlator_init(struct xlator *jool, struct config_prefix6 *pool6)
{
	return xlat_is_siit()
			? init_siit(jool, pool6)
			: init_nat64(jool, pool6);
}

static bool xlator_matches(struct xlator *jool, struct net *ns, jframework fw,
		const char *iname)
{
	return (jool->ns == ns)
			&& (jool->fw & fw)
			&& (!iname || strcmp(jool->iname, iname) == 0);
}

/**
 * Basic validations when adding an xlator to the DB.
 */
static int basic_add_validations(jframework fw, char *iname,
		struct config_prefix6 *pool6)
{
	int error;

	error = iname_validate(iname, false);
	if (error)
		return error;
	error = fw_validate(fw);
	if (error)
		return error;
	if (xlat_is_nat64() && (!pool6 || !pool6->set)) {
		log_err("pool6 is mandatory in NAT64 instances.");
		return -EINVAL;
	}

	return 0;
}

/**
 * Checks whether an instance (whose namespace is @ns, its framework is @fw,
 * and its name is @iname) can be added to the database without breaking its
 * rules.
 *
 * Assumes the DB mutex is locked.
 */
static int validate_collision(struct net *ns, jframework fw, char *iname)
{
	struct list_head *list;
	struct jool_instance *instance;

	/* Shuts up the RCU police. Not actually needed because of the mutex. */
	rcu_read_lock_bh();

	list = rcu_dereference_bh(pool);
	list_for_each_entry_rcu(instance, list, list_hook) {
		if (instance->jool.ns != ns)
			continue;

		if (strcmp(instance->jool.iname, iname) == 0) {
			log_err("This namespace already has a Jool instance named '%s'.",
					iname);
			goto eexist;
		}

		if ((fw & FW_NETFILTER) && (instance->jool.fw & FW_NETFILTER)) {
			log_err("This namespace already has a Netfilter Jool instance.");
			goto eexist;
		}
	}

	rcu_read_unlock_bh();
	return 0;

eexist:
	rcu_read_unlock_bh();
	return -EEXIST;
}

/**
 * Requires the mutex to be locked.
 */
int __xlator_add(struct jool_instance *new, struct xlator *result)
{
	struct list_head *list;

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	if (new->jool.fw & FW_NETFILTER) {
		struct nf_hook_ops *ops;
		int error;

		ops = __wkmalloc("nf_hook_ops", 2 * sizeof(struct nf_hook_ops),
				GFP_KERNEL);
		if (!ops)
			return -ENOMEM;

		/* All error roads from now need to free @ops. */

		init_nf_hook_op6(&ops[0]);
		init_nf_hook_op4(&ops[1]);

		error = nf_register_net_hooks(new->jool.ns, ops, 2);
		if (error) {
			__wkfree("nf_hook_ops", ops);
			return error;
		}

		new->nf_ops = ops;
	}
#endif

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_add_tail_rcu(&new->list_hook, list);

	defrag_enable(new->jool.ns);

	if (result) {
		xlator_get(&new->jool);
		memcpy(result, &new->jool, sizeof(new->jool));
	}

	return 0;
}

/**
 * xlator_add - Whenever called, starts translation of packets traveling through
 * the namespace running in the caller's context.
 * @result: Will be initialized with a reference to the new translator. Send
 *     NULL if you're not interested.
 */
int xlator_add(jframework fw, char *iname, struct config_prefix6 *pool6,
		struct xlator *result)
{
	struct jool_instance *instance;
	struct net *ns;
	int error;

	error = basic_add_validations(fw, iname, pool6);
	if (error)
		return error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	/* All roads from now need to put @ns. */

	instance = wkmalloc(struct jool_instance, GFP_KERNEL);
	if (!instance) {
		put_net(ns);
		return -ENOMEM;
	}

	/* All *error* roads from now need to free @instance. */

	strcpy(instance->jool.iname, iname);
	instance->jool.fw = fw;
	instance->jool.ns = ns;
	error = xlator_init(&instance->jool, pool6);
	if (error) {
		wkfree(struct jool_instance, instance);
		put_net(ns);
		return error;
	}
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
	instance->nf_ops = NULL;
#endif

	/* Error roads from now no longer need to free @instance. */
	/* Error roads from now need to properly destroy @instance. */

	mutex_lock(&lock);

	/* All roads from now on must unlock the mutex. */

	error = validate_collision(ns, fw, iname);
	if (error)
		goto mutex_fail;

	error = __xlator_add(instance, result);
	if (error)
		goto mutex_fail;

	mutex_unlock(&lock);
	put_net(ns);
	log_info("Created instance '%s'.", iname);
	return 0;

mutex_fail:
	mutex_unlock(&lock);
	destroy_jool_instance(instance, false);
	put_net(ns);
	return error;
}

static int __xlator_rm(struct net *ns, char *iname)
{
	struct list_head *list;
	struct jool_instance *instance;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry(instance, list, list_hook) {
		if (xlator_matches(&instance->jool, ns, FW_ANY, iname)) {
			list_del_rcu(&instance->list_hook);
			mutex_unlock(&lock);

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
			destroy_jool_instance(instance, true);
			return 0;
		}
	}

	mutex_unlock(&lock);
	return -ESRCH;
}

int xlator_rm(char *iname)
{
	struct net *ns;
	int error;

	error = iname_validate(iname, false);
	if (error)
		return error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = __xlator_rm(ns, iname);
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
	int error;

	error = basic_add_validations(jool->fw, jool->iname,
			&jool->global->cfg.pool6);
	if (error)
		return error;

	new = wkmalloc(struct jool_instance, GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	memcpy(&new->jool, jool, sizeof(*jool));
	xlator_get(&new->jool);
	new->nf_ops = NULL;

	mutex_lock(&lock);

	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
	list_for_each_entry_rcu(old, list, list_hook) {
		if (xlator_equals(&old->jool, &new->jool)) {
#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
			new->nf_ops = old->nf_ops;
#endif
			/*
			 * The old BIB and joold must survive, because they
			 * shouldn't be reset by atomic configuration.
			 */
			if (xlat_is_nat64()) {
				bib_put(new->jool.nat64.bib);
				joold_put(new->jool.nat64.joold);
				new->jool.nat64.bib = old->jool.nat64.bib;
				new->jool.nat64.joold = old->jool.nat64.joold;
			}

			list_replace_rcu(&old->list_hook, &new->list_hook);
			mutex_unlock(&lock);

			synchronize_rcu_bh();

#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
			old->nf_ops = NULL;
#endif
			if (xlat_is_nat64()) {
				old->jool.nat64.bib = NULL;
				old->jool.nat64.joold = NULL;
			}

			log_info("Created instance '%s'.", jool->iname);
			destroy_jool_instance(old, false);
			return 0;
		}
	}

	/* Not found, hence not replacing. Add it instead. */
	error = __xlator_add(new, NULL);
	if (error)
		destroy_jool_instance(new, false);

	mutex_unlock(&lock);
	return error;
}

int xlator_flush(void)
{
	struct net *ns;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	flush_net(ns);

	put_net(ns);
	return 0;
}

/**
 * xlator_find - Returns the first instance in the database that matches @ns,
 * @fw and @iname.
 *
 * A result value of 0 means success, -ESRCH means that this namespace has no
 * instance, -EINVAL means that @iname is not a valid instance name.
 * @result will be populated with the instance. Send NULL if all you want is to
 * test whether it exists or not.
 * If not NULL, please xlator_put() @result when you're done using it.
 *
 * @iname is allowed to be NULL. Do this when you don't care about the instace's
 * name; you just want one that matches both @ns and @fw.
 *
 * IT IS EXTREMELY IMPORTANT THAT YOU NEVER KREF_GET ANY OF @result'S MEMBERS!!!
 * (You are not meant to fork pointers to them.)
 */
int xlator_find(struct net *ns, jframework fw, const char *iname,
		struct xlator *result)
{
	struct list_head *list;
	struct jool_instance *instance;
	int error;

	/*
	 * There is at least one caller to this function which cares about error
	 * code. You need to review it if you want to add or reuse error codes.
	 */

	error = iname_validate(iname, true);
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
int xlator_find_current(jframework fw, const char *iname, struct xlator *result)
{
	struct net *ns;
	int error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	error = xlator_find(ns, fw, iname, result);

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
	jstat_put(jool->stats);
	config_put(jool->global);

	if (xlat_is_siit()) {
		eamt_put(jool->siit.eamt);
		blacklist_put(jool->siit.blacklist);
	} else {
		/*
		 * Welp. There is no nf_defrag_ipv*_disable(). Guess we'll just
		 * have to leave those modules around.
		 */
		pool4db_put(jool->nat64.pool4);
		if (jool->nat64.bib)
			bib_put(jool->nat64.bib);
		if (jool->nat64.joold)
			joold_put(jool->nat64.joold);
	}
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
