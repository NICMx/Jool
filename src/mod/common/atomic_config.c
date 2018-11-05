#include "mod/common/atomic_config.h"

#include <linux/kref.h>
#include <linux/timer.h>
#include "mod/common/nl/global.h"
#include "mod/common/wkmalloc.h"
#include "mod/siit/eam.h"
#include "mod/siit/pool.h"
#include "mod/nat64/joold.h"
#include "mod/nat64/pool4/db.h"
#include "mod/nat64/bib/db.h"

/**
 * This represents the new configuration the user wants to apply to a certain
 * Jool instance.
 *
 * On account that the tables can hold any amount of entries, the configuration
 * can be quite big, so it is quite plausible it might not entirely fit in a
 * single Netlink message. So, in order to guarantee a configuration file is
 * loaded atomically, the values are stored in a separate container (a
 * "configuration candidate") as Netlink messages arrive. The running
 * configuration is then only replaced when the candidate has been completed and
 * validated.
 *
 * In an ideal world, a configuration candidate would be a plain struct xlator,
 * but because of the way basic data types and the kref are handled, the
 * candidate needs a slightly different layout.
 */
struct config_candidate {
	struct xlator xlator;

	/** Last jiffy the user made an edit. */
	unsigned long update_time;
	/** Process ID of the client that is populating this candidate. */
	pid_t pid;

	struct list_head list_hook;
};

/**
 * We'll purge candidates after they've been inactive for this long.
 * This is because otherwise we depend on userspace sending us a commit at some
 * point, and we don't trust them.
 */
#define TIMEOUT msecs_to_jiffies(2000)

static LIST_HEAD(db);
static DEFINE_MUTEX(lock);

static void candidate_destroy(struct config_candidate *candidate)
{
	log_debug("Destroying atomic configuration candidate '%s'.",
			candidate->xlator.iname);
	xlator_put(&candidate->xlator);
	list_del(&candidate->list_hook);
	wkfree(struct config_candidate, candidate);
}

static void candidate_expire_maybe(struct config_candidate *candidate)
{
	/*
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
	if (time_after(jiffies, candidate->update_time + TIMEOUT))
		candidate_destroy(candidate);
}

/**
 * Returns the instance candidate whose namespace is the current one and whose
 * name is @iname, creating it if necessary.
 */
static int get_candidate(char *iname, struct config_candidate **result)
{
	struct net *ns;
	struct config_candidate *candidate;
	struct config_candidate *tmp;
	int error;

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		log_err("Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	list_for_each_entry_safe(candidate, tmp, &db, list_hook) {
		if ((candidate->xlator.ns == ns)
				&& (strcmp(candidate->xlator.iname, iname) == 0)
				&& (candidate->pid == task_pid_nr(current)))
			goto success;

		candidate_expire_maybe(candidate);
	}

	candidate = wkmalloc(struct config_candidate, GFP_KERNEL);
	if (!candidate) {
		put_net(ns);
		return -ENOMEM;
	}

	/*
	 * fw and pool6 are basic configuration that we can't populate yet.
	 * Those must be handled later.
	 */
	error = xlator_init(&candidate->xlator, ns, 0, iname, NULL);
	if (error) {
		wkfree(struct config_candidate, candidate);
		put_net(ns);
		return error;
	}
	candidate->update_time = jiffies;
	candidate->pid = task_pid_nr(current);
	list_add(&candidate->list_hook, &db);
	/* Fall through */

success:
	*result = candidate;
	put_net(ns);
	return 0;
}

static int handle_init(struct config_candidate *new, void *payload,
		__u32 payload_len)
{
	struct request_init *request = payload;
	int error;

	error = fw_validate(request->fw);
	if (error)
		return error;

	new->xlator.fw = request->fw;
	return 0;
}

static int handle_global(struct config_candidate *new, void *payload,
		__u32 payload_len, bool force)
{
	int result;

	do {
		result = global_update(new->xlator.global, force,
				payload, payload_len);
		if (result < 0)
			return result;

		payload += result;
		payload_len -= result;
	} while (payload_len > 0);

	return 0;
}

static int handle_eamt(struct config_candidate *new, void *payload,
		__u32 payload_len, bool force)
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

	for (i = 0; i < eam_count; i++) {
		eam = &eams[i];
		error = eamt_add(new->xlator.siit.eamt, &eam->prefix6,
				&eam->prefix4, force);
		if (error)
			return error;
	}

	return 0;
}

static int handle_blacklist4(struct config_candidate *new, void *payload,
		__u32 payload_len, bool force)
{
	struct ipv4_prefix *prefixes = payload;
	unsigned int prefix_count = payload_len / sizeof(*prefixes);
	unsigned int i;
	int error;

	if (xlat_is_nat64()) {
		log_err("Stateful NAT64 doesn't have IPv4 address pools.");
		return -EINVAL;
	}

	for (i = 0; i < prefix_count; i++) {
		error = pool_add(new->xlator.siit.blacklist4, &prefixes[i],
				force);
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

	if (xlat_is_siit()) {
		log_err("SIIT doesn't have pool4.");
		return -EINVAL;
	}

	for (i = 0; i < entry_count; i++) {
		error = pool4db_add(new->xlator.nat64.pool4, &entries[i]);
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

static int commit(struct config_candidate *candidate)
{
	int error;

	error = xlator_replace(&candidate->xlator);
	if (error) {
		log_err("xlator_replace() failed. Errcode %d", error);
		return error;
	}

	candidate_destroy(candidate);
	log_debug("The atomic configuration transaction was a success.");
	return 0;
}

int atomconfig_add(char *iname, void *config, size_t config_len, bool force)
{
	struct config_candidate *candidate = NULL;
	__u16 type = *((__u16 *)config);
	int error;

	error = iname_validate(iname, false);
	if (error)
		return error;

	config += sizeof(type);
	config_len -= sizeof(type);

	mutex_lock(&lock);

	error = get_candidate(iname, &candidate);
	if (error) {
		mutex_unlock(&lock);
		return error;
	}

	switch (type) {
	case SEC_INIT:
		error = handle_init(candidate, config, config_len);
		break;
	case SEC_GLOBAL:
		error = handle_global(candidate, config, config_len, force);
		break;
	case SEC_EAMT:
		error = handle_eamt(candidate, config, config_len, force);
		break;
	case SEC_BLACKLIST:
		error = handle_blacklist4(candidate, config, config_len, force);
		break;
	case SEC_POOL4:
		error = handle_pool4(candidate, config, config_len);
		break;
	case SEC_BIB:
		error = handle_bib(candidate, config, config_len);
		break;
	case SEC_COMMIT:
		error = commit(candidate);
		break;
	default:
		log_err("Unknown configuration mode.");
		error = -EINVAL;
		break;
	}

	if (error)
		candidate_destroy(candidate);
	else
		candidate->update_time = jiffies;

	mutex_unlock(&lock);
	return error;
}
