#include "nat64/mod/common/atomic_config.h"

#include "nat64/mod/common/nl/global.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/common/wkmalloc.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/pool.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/joold.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/bib/db.h"

/**
 * We'll purge candidates after they've been inactive for this long.
 * This is because otherwise we depend on userspace sending us a commit at some
 * point, and we don't trust them.
 */
#define TIMEOUT msecs_to_jiffies(2000)

static DEFINE_MUTEX(lock);

static void candidate_clean(struct config_candidate *candidate)
{
	if (candidate->global) {
		wkfree(struct full_config, candidate->global);
		candidate->global = NULL;
	}
	if (candidate->pool6) {
		pool6_put(candidate->pool6);
		candidate->pool6 = NULL;
	}
	if (xlat_is_siit()) {
		if (candidate->siit.eamt) {
			/*
			 * TODO (critical) kernel panic here.
			 * candidate_clean() is called on a timer, which cannot
			 * sleep, but eamt_put() calls synchronize_rcu_bh(),
			 * which is very sleepy.
			 */
			eamt_put(candidate->siit.eamt);
			candidate->siit.eamt = NULL;
		}
		if (candidate->siit.blacklist) {
			pool_put(candidate->siit.blacklist);
			candidate->siit.blacklist = NULL;
		}
		if (candidate->siit.pool6791) {
			pool_put(candidate->siit.pool6791);
			candidate->siit.pool6791 = NULL;
		}
	} else {
		if (candidate->nat64.pool4) {
			pool4db_put(candidate->nat64.pool4);
			candidate->nat64.pool4 = NULL;
		}
	}

	candidate->active = false;
}

static void timer_function(unsigned long arg)
{
	/*
	 * TODO (critical) kernel panic here.
	 * Timers are not allowed to sleep. mutex_lock() sleeps.
	 * Note: @lock cannot be a spinlock either because atomconfig_add()
	 * currently uses GFP_KERNEL.
	 */
	mutex_lock(&lock);
	candidate_clean((struct config_candidate *)arg);
	mutex_unlock(&lock);
}

struct config_candidate *cfgcandidate_create(void)
{
	struct config_candidate *candidate;

	candidate = wkmalloc(struct config_candidate, GFP_KERNEL);
	if (!candidate)
		return NULL;

	memset(candidate, 0, sizeof(*candidate));

	init_timer(&candidate->timer);
	candidate->timer.function = timer_function;
	candidate->timer.expires = 0;
	candidate->timer.data = (unsigned long)candidate;

	kref_init(&candidate->refcount);
	return candidate;
}

void cfgcandidate_get(struct config_candidate *candidate)
{
	kref_get(&candidate->refcount);
}

static void candidate_destroy(struct kref *refcount)
{
	struct config_candidate *candidate;
	candidate = container_of(refcount, struct config_candidate, refcount);
	candidate_clean(candidate);
	del_timer_sync(&candidate->timer);
	wkfree(struct config_candidate, candidate);
}

void cfgcandidate_put(struct config_candidate *candidate)
{
	kref_put(&candidate->refcount, candidate_destroy);
}

static void rollback(struct xlator *jool)
{
	candidate_clean(jool->newcfg);
}

static int handle_global(struct xlator *jool, void *payload, __u32 payload_len)
{
	struct full_config *config;
	int result;

	config = jool->newcfg->global;
	if (!config) {
		config = wkmalloc(struct full_config, GFP_KERNEL);
		if (!config)
			return -ENOMEM;
		xlator_copy_config(jool, config);

		jool->newcfg->global = config;
	}

	/*
	 * TODO (issue164) if there's an error in config_parse, this can easily
	 * fall into an infinite loop. An attacker could abuse this.
	 * Maybe add validations?
	 */

	do {
		result = config_parse(config, payload, payload_len);
		if (result < 0)
			return result;

		payload += result;
		payload_len -= result;
	} while (payload_len > 0);

	return 0;
}

static int handle_pool6(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	struct ipv6_prefix *prefixes = payload;
	unsigned int prefix_count = payload_len / sizeof(*prefixes);
	unsigned int i;
	int error;

	if (!new->pool6) {
		error = pool6_init(&new->pool6);
		if (error)
			return error;
	}

	for (i = 0; i < prefix_count; i++) {
		error = pool6_add(new->pool6, &prefixes[i]);
		if (error)
			return error;
	}

	return 0;
}

static int handle_eamt(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	struct eamt_entry *eams = payload;
	unsigned int eam_count = payload_len / sizeof(*eams);
	struct eamt_entry *eam;
	unsigned int i;
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have an EAMT.");
		return -EINVAL;
	}

	if (!new->siit.eamt) {
		error = eamt_init(&new->siit.eamt);
		if (error)
			return error;
	}

	for (i = 0; i < eam_count; i++) {
		eam = &eams[i];
		/* TODO (issue164) force should be variable. */
		error = eamt_add(new->siit.eamt, &eam->prefix6, &eam->prefix4,
				true);
		if (error)
			return error;
	}

	return 0;
}

static int handle_addr4_pool(struct addr4_pool **pool, void *payload,
		__u32 payload_len)
{
	struct ipv4_prefix *prefixes = payload;
	unsigned int prefix_count = payload_len / sizeof(*prefixes);
	unsigned int i;
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have IPv4 address pools.");
		return -EINVAL;
	}

	if (!(*pool)) {
		error = pool_init(pool);
		if (error)
			return error;
	}

	for (i = 0; i < prefix_count; i++) {
		/* TODO (issue164) force should be variable. */
		error = pool_add(*pool, &prefixes[i], true);
		if (error)
			return error;
	}

	return 0;
}

static int handle_blacklist(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	return handle_addr4_pool(&new->siit.blacklist, payload, payload_len);
}

static int handle_pool6791(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	return handle_addr4_pool(&new->siit.pool6791, payload, payload_len);
}

static int handle_pool4(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	struct pool4_entry_usr *entries = payload;
	unsigned int entry_count = payload_len / sizeof(*entries);
	unsigned int i;
	int error;

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have pool4.");
		return -EINVAL;
	}

	if (!new->nat64.pool4) {
		error = pool4db_init(&new->nat64.pool4);
		if (error)
			return error;
	}

	for (i = 0; i < entry_count; i++) {
		error = pool4db_add_usr(new->nat64.pool4, &entries[i]);
		if (error)
			return error;
	}

	return 0;
}

static int handle_bib(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	if (xlat_is_siit()) {
		log_err("SIIT doesn't have BIBs.");
		return -EINVAL;
	}

	log_err("Atomic configuration of the BIB is not implemented.");
	return -EINVAL;
}

static int commit(struct xlator *jool)
{
	struct config_candidate *new = jool->newcfg;
	struct global_config *global;
	struct full_config *remnants = NULL;
	int error;

	/*
	 * Reminder: Our @jool is a copy of the one stored in the xlator DB.
	 * Nobody else is refencing it.
	 * (But the objects pointed by @jool's members can be shared.)
	 */

	if (new->global) {
		error = config_init(&global);
		if (error)
			return error;
		config_copy(&new->global->global, &global->cfg);

		remnants = new->global;

		config_put(jool->global);
		jool->global = global;
		new->global = NULL;
	}
	if (new->pool6) {
		pool6_put(jool->pool6);
		jool->pool6 = new->pool6;
		new->pool6 = NULL;
	}

	if (xlat_is_siit()) {
		if (new->siit.eamt) {
			eamt_put(jool->siit.eamt);
			jool->siit.eamt = new->siit.eamt;
			new->siit.eamt = NULL;
		}
		if (new->siit.blacklist) {
			pool_put(jool->siit.blacklist);
			jool->siit.blacklist = new->siit.blacklist;
			new->siit.blacklist = NULL;
		}
		if (new->siit.pool6791) {
			pool_put(jool->siit.pool6791);
			jool->siit.pool6791 = new->siit.pool6791;
			new->siit.pool6791 = NULL;
		}
	} else {
		if (new->nat64.pool4) {
			pool4db_put(jool->nat64.pool4);
			jool->nat64.pool4 = new->nat64.pool4;
			new->nat64.pool4 = NULL;
		}
	}

	error = xlator_replace(jool);
	if (error) {
		log_err("xlator_replace() failed. Errcode %d", error);
		return error;
	}

	/*
	 * This the little flaw in the design.
	 * I can't make full new versions of BIB, joold and frag just
	 * over a few configuration values because the tables can be massive,
	 * so instead I'm patching values after I know the pointer swap was
	 * successful.
	 * Because they can't fail there are no dire consequences, but you know.
	 * These look a little out of place.
	 */
	if (remnants) {
		bib_config_set(jool->nat64.bib, &remnants->bib);
		joold_config_set(jool->nat64.joold, &remnants->joold);
		fragdb_config_set(jool->nat64.frag, &remnants->frag);
		wkfree(struct full_config, remnants);
	}

	jool->newcfg->active = false;
	log_debug("Configuration replaced.");
	return 0;
}

int atomconfig_add(struct xlator *jool, void *config, size_t config_len)
{
	__u16 type = *((__u16 *)config);
	int error;

	config += sizeof(type);
	config_len -= sizeof(type);

	mutex_lock(&lock);

	if (jool->newcfg->active) {
		if (jool->newcfg->pid != current->pid) {
			log_err("There's another atomic configuration underway. Please try again later.");
			mutex_unlock(&lock);
			return -EAGAIN;
		}
	} else {
		jool->newcfg->active = true;
		jool->newcfg->pid = current->pid;
	}

	switch (type) {
	case SEC_INIT:
		rollback(jool);
		error = 0;
		break;
	case SEC_GLOBAL:
		error = handle_global(jool, config, config_len);
		break;
	case SEC_POOL6:
		error = handle_pool6(jool->newcfg, config, config_len);
		break;
	case SEC_EAMT:
		error = handle_eamt(jool->newcfg, config, config_len);
		break;
	case SEC_BLACKLIST:
		error = handle_blacklist(jool->newcfg, config, config_len);
		break;
	case SEC_POOL6791:
		error = handle_pool6791(jool->newcfg, config, config_len);
		break;
	case SEC_POOL4:
		error = handle_pool4(jool->newcfg, config, config_len);
		break;
	case SEC_BIB:
		error = handle_bib(jool->newcfg, config, config_len);
		break;
	case SEC_COMMIT:
		error = commit(jool);
		break;
	default:
		log_err("Unknown configuration mode.");
		error = -EINVAL;
		break;
	}

	if (error)
		rollback(jool);
	else
		mod_timer(&jool->newcfg->timer, jiffies + TIMEOUT);

	mutex_unlock(&lock);
	return error;
}

void cfgcandidate_print_refcount(struct config_candidate *candidate)
{
	log_info("cfg candidate: %d", atomic_read(&candidate->refcount.refcount));
}
