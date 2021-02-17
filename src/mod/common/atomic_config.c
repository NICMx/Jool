#include "mod/common/atomic_config.h"

#include <linux/kref.h>
#include <linux/timer.h>
#include "mod/common/log.h"
#include "mod/common/wkmalloc.h"
#include "mod/common/nl/attribute.h"
#include "mod/common/nl/global.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/db/eam.h"
#include "mod/common/db/denylist4.h"
#include "mod/common/db/fmr.h"
#include "mod/common/joold.h"
#include "mod/common/db/pool4/db.h"
#include "mod/common/db/bib/db.h"

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
	LOG_DEBUG("Destroying atomic configuration candidate '%s'.",
			candidate->xlator.iname);
	xlator_put(&candidate->xlator);
	list_del(&candidate->list_hook);
	wkfree(struct config_candidate, candidate);
}

void atomconfig_teardown(void)
{
	struct config_candidate *candidate;
	struct config_candidate *tmp;

	list_for_each_entry_safe(candidate, tmp, &db, list_hook)
		candidate_destroy(candidate);
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

static int check_xtype(struct jnl_state *state, xlator_type expected,
		char const *what)
{
	xlator_type actual;

	actual = xlator_get_type(jnls_xlator(state));
	if (!(actual & expected)) {
		return jnls_err(state, "%s translators don't have %ss.",
				xt2str(actual), what);
	}

	return 0;
}

/**
 * Returns the instance candidate whose namespace is the current one and whose
 * name is @iname.
 */
static int get_candidate(struct jnl_state *state, char *iname,
		struct config_candidate **result)
{
	struct net *ns;
	struct config_candidate *candidate;
	struct config_candidate *tmp;

	LOG_DEBUG("Handling subsequent attribute.");

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		jnls_err(state, "Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	list_for_each_entry_safe(candidate, tmp, &db, list_hook) {
		if ((candidate->xlator.ns == ns)
				&& (strcmp(candidate->xlator.iname, iname) == 0)
				&& (candidate->pid == task_pid_nr(current))) {
			jnls_set_xlator(state, &candidate->xlator);
			*result = candidate;
			put_net(ns);
			return 0;
		}

		candidate_expire_maybe(candidate);
	}

	jnls_err(state, "Instance not found.");
	return -ESRCH;
}

static int handle_init(struct jnl_state *state, struct config_candidate **out,
		struct nlattr *attr, char *iname, xlator_type xt)
{
	struct config_candidate *candidate;
	struct net *ns;
	int error;

	LOG_DEBUG("Handling atomic INIT attribute.");

	ns = get_net_ns_by_pid(task_pid_vnr(current));
	if (IS_ERR(ns)) {
		jnls_err(state, "Could not retrieve the current namespace.");
		return PTR_ERR(ns);
	}

	candidate = wkmalloc(struct config_candidate, GFP_KERNEL);
	if (!candidate) {
		error = -ENOMEM;
		goto end;
	}

	error = xlator_init(&candidate->xlator, ns, iname,
			nla_get_u8(attr) | xt, NULL, state);
	if (error) {
		wkfree(struct config_candidate, candidate);
		goto end;
	}
	candidate->update_time = jiffies;
	candidate->pid = task_pid_nr(current);
	list_add(&candidate->list_hook, &db);
	*out = candidate;

	jnls_set_xlator(state, &candidate->xlator);
	/* Fall through */

end:	put_net(ns);
	return error;
}

static int handle_global(struct jnl_state *state, struct nlattr *attr,
		joolnlhdr_flags flags)
{
	struct xlator *jool = jnls_xlator(state);

	LOG_DEBUG("Handling atomic global attribute.");
	return global_update(&jool->globals, xlator_flags2xt(jool->flags),
			!!(flags & JOOLNLHDR_FLAGS_FORCE), attr, state);
}

static int handle_eamt(struct jnl_state *state, struct nlattr *root, bool force)
{
	struct nlattr *attr;
	struct eamt_entry entry;
	int rem;
	int error;

	LOG_DEBUG("Handling atomic EAMT attribute.");

	error = check_xtype(state, XT_SIIT, "EAMT");
	if (error)
		return error;

	nla_for_each_nested(attr, root, rem) {
		if (nla_type(attr) != JNLAL_ENTRY)
			continue; /* ? */
		error = jnla_get_eam(attr, "EAMT entry", &entry, state);
		if (error)
			return error;
		error = eamt_add(jnls_xlator(state)->siit.eamt, &entry, force,
				state);
		if (error)
			return error;
	}

	return 0;
}

static int handle_denylist4(struct jnl_state *state, struct nlattr *root,
		bool force)
{
	struct nlattr *attr;
	struct ipv4_prefix entry;
	int rem;
	int error;

	LOG_DEBUG("Handling atomic denylist4 attribute.");

	error = check_xtype(state, XT_SIIT, "denylist4");
	if (error)
		return error;

	nla_for_each_nested(attr, root, rem) {
		if (nla_type(attr) != JNLAL_ENTRY)
			continue; /* ? */
		error = jnla_get_prefix4(attr, "IPv4 denylist4 entry", &entry,
				state);
		if (error)
			return error;
		error = denylist4_add(jnls_xlator(state)->siit.denylist4,
				&entry, force, state);
		if (error)
			return error;
	}

	return 0;
}

static int handle_pool4(struct jnl_state *state, struct nlattr *root)
{
	struct nlattr *attr;
	struct pool4_entry entry;
	int rem;
	int error;

	LOG_DEBUG("Handling atomic pool4 attribute.");

	error = check_xtype(state, XT_NAT64, "pool4");
	if (error)
		return error;

	nla_for_each_nested(attr, root, rem) {
		if (nla_type(attr) != JNLAL_ENTRY)
			continue; /* ? */
		error = jnla_get_pool4(attr, "pool4 entry", &entry, state);
		if (error)
			return error;
		error = pool4db_add(jnls_xlator(state)->nat64.pool4, &entry,
				state);
		if (error)
			return error;
	}

	return 0;
}

static int handle_bib(struct jnl_state *state, struct nlattr *root)
{
	struct nlattr *attr;
	struct bib_entry entry;
	int rem;
	int error;

	LOG_DEBUG("Handling atomic BIB attribute.");

	error = check_xtype(state, XT_NAT64, "BIB");
	if (error)
		return error;

	nla_for_each_nested(attr, root, rem) {
		if (nla_type(attr) != JNLAL_ENTRY)
			continue; /* ? */
		error = jnla_get_bib(attr, "BIB entry", &entry, state);
		if (error)
			return error;
		error = bib_add_static(jnls_xlator(state)->nat64.bib, &entry,
				state);
		if (error)
			return error;
	}

	return 0;
}

static int handle_fmrt(struct jnl_state *state, struct nlattr *root)
{
	struct nlattr *attr;
	struct config_mapping_rule entry;
	int rem;
	int error;

	LOG_DEBUG("Handling atomic FMRT attribute.");

	error = check_xtype(state, XT_MAPT, "FMRT");
	if (error)
		return error;

	nla_for_each_nested(attr, root, rem) {
		if (nla_type(attr) != JNLAL_ENTRY)
			continue; /* ? */
		error = jnla_get_mapping_rule(attr, "FMR", &entry, state);
		if (error)
			return error;
		if (!entry.set)
			return jnls_err(state, "FMR is empty.");
		error = fmrt_add(jnls_xlator(state)->mapt.fmrt, &entry.rule,
				state);
		if (error)
			return error;
	}

	return 0;
}

static int commit(struct jnl_state *state, struct config_candidate *candidate)
{
	int error;

	LOG_DEBUG("Handling atomic END attribute.");

	error = xlator_replace(&candidate->xlator, state);
	if (error) {
		jnls_err(state, "xlator_replace() failed. Errcode %d", error);
		return error;
	}

	candidate_destroy(candidate);
	LOG_DEBUG("The atomic configuration transaction was a success.");
	return 0;
}

int atomconfig_add(struct jnl_state *state, struct genl_info const *info)
{
	struct config_candidate *candidate;
	struct joolnlhdr *jhdr;
	int error;

	candidate = NULL;
	jhdr = jnls_jhdr(state);

	error = iname_validate(jhdr->iname, false);
	if (error) {
		jnls_err(state, INAME_VALIDATE_ERRMSG);
		return error;
	}

	mutex_lock(&lock);

	error = info->attrs[JNLAR_ATOMIC_INIT]
			? handle_init(state, &candidate,
					info->attrs[JNLAR_ATOMIC_INIT],
					jhdr->iname, jhdr->xt)
			: get_candidate(state, jhdr->iname, &candidate);
	if (error)
		goto end;

	if (info->attrs[JNLAR_GLOBALS]) {
		error = handle_global(state, info->attrs[JNLAR_GLOBALS],
				jhdr->flags);
		if (error)
			goto revert;
	}
	if (info->attrs[JNLAR_BL4_ENTRIES]) {
		error = handle_denylist4(state, info->attrs[JNLAR_BL4_ENTRIES],
				jhdr->flags & JOOLNLHDR_FLAGS_FORCE);
		if (error)
			goto revert;
	}
	if (info->attrs[JNLAR_EAMT_ENTRIES]) {
		error = handle_eamt(state, info->attrs[JNLAR_EAMT_ENTRIES],
				jhdr->flags & JOOLNLHDR_FLAGS_FORCE);
		if (error)
			goto revert;
	}
	if (info->attrs[JNLAR_POOL4_ENTRIES]) {
		error = handle_pool4(state, info->attrs[JNLAR_POOL4_ENTRIES]);
		if (error)
			goto revert;
	}
	if (info->attrs[JNLAR_BIB_ENTRIES]) {
		error = handle_bib(state, info->attrs[JNLAR_BIB_ENTRIES]);
		if (error)
			goto revert;
	}
	if (info->attrs[JNLAR_FMRT_ENTRIES]) {
		error = handle_fmrt(state, info->attrs[JNLAR_FMRT_ENTRIES]);
		if (error)
			goto revert;
	}
	if (info->attrs[JNLAR_ATOMIC_END]) {
		error = commit(state, candidate);
		if (error)
			goto revert;
	}

	candidate->update_time = jiffies;
	goto end;

revert:
	candidate_destroy(candidate);
end:
	jnls_set_xlator(state, NULL);
	mutex_unlock(&lock);
	return error;
}
