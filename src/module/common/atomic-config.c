#include "atomic-config.h"

#include "nl/nl-global.h"
#include "wkmalloc.h"
#include "siit/eam.h"
#include "nat64/joold.h"
#include "nat64/pool4/db.h"
#include "nat64/bib/db.h"

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
	if (candidate->eamt) {
		eamt_put(candidate->eamt);
		candidate->eamt = NULL;
	}
	if (candidate->pool4) {
		pool4db_put(candidate->pool4);
		candidate->pool4 = NULL;
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

static int handle_eamt(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	struct eamt_entry *eams = payload;
	unsigned int eam_count = payload_len / sizeof(*eams);
	struct eamt_entry *eam;
	unsigned int i;
	int error;

	if (!new->eamt) {
		new->eamt = eamt_init();
		if (!new->eamt)
			return -ENOMEM;
	}

	for (i = 0; i < eam_count; i++) {
		eam = &eams[i];
		/* TODO (issue164) force should be variable. */
		error = eamt_add(new->eamt, &eam->prefix6, &eam->prefix4, true);
		if (error)
			return error;
	}

	return 0;
}

static int handle_pool4(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	struct pool4_entry_usr *entries = payload;
	unsigned int entry_count = payload_len / sizeof(*entries);
	unsigned int i;
	int error;

	if (!new->pool4) {
		new->pool4 = pool4db_init();
		if (!new->pool4)
			return -ENOMEM;
	}

	for (i = 0; i < entry_count; i++) {
		error = pool4db_add(new->pool4, &entries[i]);
		if (error)
			return error;
	}

	return 0;
}

static int handle_bib(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
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
		global = config_init();
		if (!global)
			return -ENOMEM;
		config_copy(&new->global->global, &global->cfg);

		remnants = new->global;

		config_put(jool->global);
		jool->global = global;
		new->global = NULL;
	}
	if (new->eamt) {
		eamt_put(jool->eamt);
		jool->eamt = new->eamt;
		new->eamt = NULL;
	}
	if (new->pool4) {
		pool4db_put(jool->pool4);
		jool->pool4 = new->pool4;
		new->pool4 = NULL;
	}

	error = xlator_replace(jool);
	if (error) {
		log_err("xlator_replace() failed. Errcode %d", error);
		return error;
	}

	/*
	 * This the little flaw in the design.
	 * I can't make full new versions of BIB and joold just
	 * over a few configuration values because the tables can be massive,
	 * so instead I'm patching values after I know the pointer swap was
	 * successful.
	 * Because they can't fail there are no dire consequences, but you know.
	 * These look a little out of place.
	 */
	if (remnants) {
		bib_config_set(jool->bib, &remnants->bib);
		joold_config_set(jool->joold, &remnants->joold);
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
	case SEC_EAMT:
		error = handle_eamt(candidate, config, config_len);
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
