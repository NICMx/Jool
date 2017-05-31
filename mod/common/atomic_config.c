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

struct config_candidate *cfgcandidate_create(void)
{
	struct config_candidate *candidate;

	candidate = wkmalloc(struct config_candidate, GFP_KERNEL);
	if (!candidate)
		return NULL;

	memset(candidate, 0, sizeof(*candidate));

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
	struct config_candidate *candidate;
	__u16 type = *((__u16 *)config);
	int error;

	config += sizeof(type);
	config_len -= sizeof(type);

	mutex_lock(&lock);
	candidate = jool->newcfg;

	/*
	 * I should explain this if.
	 *
	 * The userspace application makes a series of requests which we pile
	 * up in @candidate. If any of them fails, the @candidate is rolled
	 * back. When the app finishes, it states so by requesting a commit.
	 * But we don't trust the app. What happens if it dies before sending
	 * the commit?
	 *
	 * Well, the candidate needs to expire.
	 *
	 * The natural solution to that would be a kernel timer, right? So why
	 * is that nowhere to be found?
	 * Because a timer would force us to synchronize access to @candidate
	 * with a spinlock. (Mutexes kill timers.) That would also be incorrect
	 * because all the handle_* functions below (which the spinlock would
	 * also need to protect) can sleep for a variety of reasons.
	 *
	 * So instead, if the userspace app dies too early to send a commit, we
	 * will hold the candidate until another atomic configuration request is
	 * made and this if realizes that the previous one expired.
	 *
	 * So what prevents a commitless sequence of requests from claiming
	 * memory pointlessly (other than another sequence of requests)?
	 * Nothing. But if they were done out of malice, then the system has
	 * much more to fear because it means the attacker has sudo. And if they
	 * were not, the user will follow shortly with another request or kill
	 * the NAT64 instance. So the @candidate will be released in the end
	 * despite the fuss. It's not a memory leak, after all.
	 *
	 * I'd like to clarify I would rather see a better solution, but I
	 * genuinely feel like making the handle_*() functions atomic is not it.
	 */
	if (candidate->update_time + TIMEOUT < jiffies)
		candidate_clean(candidate);

	if (candidate->active) {
		if (candidate->pid != current->pid) {
			log_err("There's another atomic configuration underway. Please try again later.");
			mutex_unlock(&lock);
			return -EAGAIN;
		}
	} else {
		candidate->active = true;
		candidate->pid = current->pid;
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
		error = handle_pool6(candidate, config, config_len);
		break;
	case SEC_EAMT:
		error = handle_eamt(candidate, config, config_len);
		break;
	case SEC_BLACKLIST:
		error = handle_blacklist(candidate, config, config_len);
		break;
	case SEC_POOL6791:
		error = handle_pool6791(candidate, config, config_len);
		break;
	case SEC_POOL4:
		error = handle_pool4(candidate, config, config_len);
		break;
	case SEC_BIB:
		error = handle_bib(candidate, config, config_len);
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
		candidate->update_time = jiffies;

	mutex_unlock(&lock);
	return error;
}
