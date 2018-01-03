#include "xlator.h"

#include "atomic-config.h"
#include "module-stats.h"
#include "siit/eam.h"
#include "nat64/joold.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

void xlator_get(struct xlator *jool)
{
	jstat_get(jool->stats);
	config_get(jool->global);
	/* TODO
	cfgcandidate_get(jool->newcfg);
	*/
	eamt_get(jool->eamt);
	pool4db_get(jool->pool4);
	bib_get(jool->bib);
	joold_get(jool->joold);
}

int xlator_add(struct xlator *jool)
{
	jool->stats = jstat_alloc();
	if (!jool->stats)
		goto stats_fail;
	jool->global = config_init();
	if (!jool->global)
		goto config_fail;
	/*
	jool->newcfg = cfgcandidate_create();
	if (!jool->newcfg)
		goto newcfg_fail;
	*/
	jool->eamt = eamt_init();
	if (!jool->eamt)
		goto eamt_fail;
	jool->pool4 = pool4db_init();
	if (!jool->pool4)
		goto pool4_fail;
	jool->bib = bib_create();
	if (!jool->bib)
		goto bib_fail;
	jool->joold = joold_create();
	if (!jool->joold)
		goto joold_fail;

	return 0;

joold_fail:
	bib_put(jool->bib);
bib_fail:
	pool4db_put(jool->pool4);
pool4_fail:
	eamt_put(jool->eamt);
eamt_fail:
	/* TODO
	cfgcandidate_put(jool->newcfg);
newcfg_fail:
	*/
	config_put(jool->global);
config_fail:
	jstat_put(jool->stats);
stats_fail:
	return -ENOMEM;
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
	jstat_put(jool->stats);
	config_put(jool->global);
	/* TODO
	cfgcandidate_put(jool->newcfg);
	*/
	eamt_put(jool->eamt);
	pool4db_put(jool->pool4);
	bib_put(jool->bib);
	joold_put(jool->joold);
}

int xlator_foreach(xlator_foreach_cb cb, void *args)
{
	/* TODO fix when you merge #257. */
	return 0;
}

//void xlator_copy_config(struct xlator *jool, struct full_config *copy)
//{
//	config_copy(&jool->global->cfg, &copy->global);
//	bib_config_copy(jool->nat64.bib, &copy->bib);
//	joold_config_copy(jool->nat64.joold, &copy->joold);
//	copy->type = jool->type;
//}
