#include "xlator.h"

//#include <linux/sched.h>

//#include "types.h"
//#include "xlat.h"
//#include "atomic-config.h"
//#include "linux-version.h"
#include "module-stats.h"
//#include "pool6.h"
//#include "wkmalloc.h"
//#include "siit/blacklist4.h"
//#include "siit/eam.h"
//#include "siit/rfc6791.h"
//#include "nat64/joold.h"
//#include "nat64/pool4/db.h"
//#include "nat64/bib/db.h"

void xlator_get(struct xlator *jool)
{
//	get_net(jool->ns);

	jstat_get(jool->stats);
//	config_get(jool->global);
//	pool6_get(jool->pool6);
//
//	switch (jool->type) {
//	case XLATOR_SIIT:
//		eamt_get(jool->siit.eamt);
//		blacklist_get(jool->siit.blacklist);
//		rfc6791_get(jool->siit.pool6791);
//		break;
//	case XLATOR_NAT64:
//		pool4db_get(jool->nat64.pool4);
//		bib_get(jool->nat64.bib);
//		joold_get(jool->nat64.joold);
//		break;
//	default:
//		BUG();
//	}
//
//	cfgcandidate_get(jool->newcfg);
}

static int init_siit(struct xlator *jool)
{
//	int error;

	jool->stats = jstat_alloc();
	if (!jool->stats)
		return -ENOMEM;
//	error = config_init(&jool->global);
//	if (error)
//		goto config_fail;
//	error = pool6_init(&jool->pool6);
//	if (error)
//		goto pool6_fail;
//	error = eamt_init(&jool->siit.eamt);
//	if (error)
//		goto eamt_fail;
//	error = blacklist_init(&jool->siit.blacklist);
//	if (error)
//		goto blacklist_fail;
//	error = rfc6791_init(&jool->siit.pool6791);
//	if (error)
//		goto rfc6791_fail;
//	jool->newcfg = cfgcandidate_create(XLATOR_SIIT);
//	if (!jool->newcfg)
//		goto newcfg_fail;

	jool->type = XLATOR_SIIT;
	return 0;

//newcfg_fail:
//	rfc6791_put(jool->siit.pool6791);
//rfc6791_fail:
//	blacklist_put(jool->siit.blacklist);
//blacklist_fail:
//	eamt_put(jool->siit.eamt);
//eamt_fail:
//	pool6_put(jool->pool6);
//pool6_fail:
//	config_put(jool->global);
//config_fail:
//	jstat_free(jool->stats);
//	return error;
}

static int init_nat64(struct xlator *jool)
{
//	int error;

	jool->stats = jstat_alloc();
	if (!jool->stats)
		return -ENOMEM;
//	error = config_init(&jool->global);
//	if (error)
//		goto config_fail;
//	error = pool6_init(&jool->pool6);
//	if (error)
//		goto pool6_fail;
//	error = pool4db_init(&jool->nat64.pool4);
//	if (error)
//		goto pool4_fail;
//	jool->nat64.bib = bib_create();
//	if (!jool->nat64.bib) {
//		error = -ENOMEM;
//		goto bib_fail;
//	}
//	jool->nat64.joold = joold_create(jool->ns);
//	if (!jool->nat64.joold) {
//		error = -ENOMEM;
//		goto joold_fail;
//	}
//
//	jool->newcfg = cfgcandidate_create(XLATOR_NAT64);
//	if (!jool->newcfg) {
//		error = -ENOMEM;
//		goto newcfg_fail;
//	}

	jool->type = XLATOR_NAT64;
	return 0;

//newcfg_fail:
//	joold_put(jool->nat64.joold);
//joold_fail:
//	bib_put(jool->nat64.bib);
//bib_fail:
//	pool4db_put(jool->nat64.pool4);
//pool4_fail:
//	pool6_put(jool->pool6);
//pool6_fail:
//	config_put(jool->global);
//config_fail:
//	return error;
}

int xlator_add(xlator_type type, struct xlator *result)
{
//	struct net *ns;
	int error;

//	ns = get_net_ns_by_pid(task_pid_vnr(current));
//	if (IS_ERR(ns)) {
//		log_err("Could not retrieve the current namespace.");
//		return PTR_ERR(ns);
//	}
//
//	result->ns = ns;
	switch (type) {
	case XLATOR_SIIT:
		error = init_siit(result);
		break;
	case XLATOR_NAT64:
		error = init_nat64(result);
		break;
	default:
		log_err("Unknown translator type: %d", type);
		error = -EINVAL;
	}

//	if (error)
//		put_net(ns);
	return error;
}

//int xlator_replace(struct xlator *jool)
//{
//	return -EINVAL;
//	/* TODO fix thins when you have the userspace app figured out.
//	struct list_head *list;
//	struct jool_instance *old;
//	struct jool_instance *new;
//
//	new = wkmalloc(struct jool_instance, GFP_KERNEL);
//	if (!new)
//		return -ENOMEM;
//	memcpy(&new->jool, jool, sizeof(*jool));
//	xlator_get(&new->jool);
//
//	mutex_lock(&lock);
//
//	list = rcu_dereference_protected(pool, lockdep_is_held(&lock));
//	list_for_each_entry_rcu(old, list, list_hook) {
//		if (old->jool.ns == new->jool.ns) {
//			/ The comments at exit_net() also apply here. /
//#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
//			new->nf_ops = old->nf_ops;
//#endif
//			list_replace_rcu(&old->list_hook, &new->list_hook);
//			mutex_unlock(&lock);
//
//			synchronize_rcu_bh();
//
//#if LINUX_VERSION_AT_LEAST(4, 13, 0, 9999, 0)
//			old->nf_ops = NULL;
//#endif
//			destroy_jool_instance(old);
//			return 0;
//		}
//	}
//
//	mutex_unlock(&lock);
//	return -ESRCH;
//	*/
//}


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
//	put_net(jool->ns);

	jstat_put(jool->stats);
//	config_put(jool->global);
//	pool6_put(jool->pool6);
//
//	switch (jool->type) {
//	case XLATOR_SIIT:
//		eamt_put(jool->siit.eamt);
//		blacklist_put(jool->siit.blacklist);
//		rfc6791_put(jool->siit.pool6791);
//		break;
//	case XLATOR_NAT64:
//		pool4db_put(jool->nat64.pool4);
//		bib_put(jool->nat64.bib);
//		joold_put(jool->nat64.joold);
//		break;
//	default:
//		BUG();
//	}
//
//	cfgcandidate_put(jool->newcfg);
}

//void xlator_copy_config(struct xlator *jool, struct full_config *copy)
//{
//	config_copy(&jool->global->cfg, &copy->global);
//	bib_config_copy(jool->nat64.bib, &copy->bib);
//	joold_config_copy(jool->nat64.joold, &copy->joold);
//	copy->type = jool->type;
//}
