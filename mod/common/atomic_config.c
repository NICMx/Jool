#include "nat64/mod/common/atomic_config.h"

#include "nat64/mod/common/nl/global.h"
#include "nat64/mod/common/pool6.h"
#include "nat64/mod/stateless/eam.h"
#include "nat64/mod/stateless/pool.h"
#include "nat64/mod/stateful/fragment_db.h"
#include "nat64/mod/stateful/bib/db.h"
#include "nat64/mod/stateful/pool4/db.h"
#include "nat64/mod/stateful/session/db.h"

/*
 * TODO (final) this module is missing a timer.
 * If the new configuration hasn't been committed after n milliseconds, newcfg
 * should be cleant.
 */

static DEFINE_MUTEX(lock);

struct config_candidate *cfgcandidate_create(void)
{
	struct config_candidate *candidate;

	candidate = kmalloc(sizeof(*candidate), GFP_KERNEL);
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

static void candidate_clean(struct config_candidate *candidate)
{
	if (candidate->global) {
		kfree(candidate->global);
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
		if (candidate->nat64.bib) {
			bibdb_put(candidate->nat64.bib);
			candidate->nat64.bib = NULL;
		}
	}
}

static void candidate_destroy(struct kref *refcount)
{
	struct config_candidate *candidate;
	candidate = container_of(refcount, typeof(*candidate), refcount);
	candidate_clean(candidate);
	kfree(candidate);
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
		config = kmalloc(sizeof(*config), GFP_KERNEL);
		if (!config)
			return -ENOMEM;
		xlator_copy_config(jool, config);

		jool->newcfg->global = config;
	}

	/*
	 * TODO if there's an error in config_parse, this can easily fall into
	 * an infinite loop.
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

	if (!new->siit.eamt) {
		error = eamt_init(&new->siit.eamt);
		if (error)
			return error;
	}

	for (i = 0; i < eam_count; i++) {
		eam = &eams[i];
		/* TODO (final) force should be variable. */
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

	if (!(*pool)) {
		error = pool_init(pool);
		if (error)
			return error;
	}

	for (i = 0; i < prefix_count; i++) {
		/* TODO (final) force should be variable. */
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

	if (!new->nat64.pool4) {
		error = pool4db_init(&new->nat64.pool4, 0);
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

static int handle_bib(struct config_candidate *new, void *payload, __u32 payload_len)
{
	struct bib_entry_usr *bibs = payload;
	unsigned int bib_count = payload_len / sizeof(*bibs);
	struct bib_entry *entry;
	unsigned int i;
	int error;

	if (!new->nat64.bib) {
		error = bibdb_init(&new->nat64.bib);
		if (error)
			return error;
	}

	for (i = 0; i < bib_count; i++) {
		entry = bibentry_create_usr(&bibs[i]);
		if (!entry)
			return -ENOMEM;

		error = bibdb_add(new->nat64.bib, entry, NULL);
		if (error)
			return error;
	}

	return 0;
}

static int commit(struct xlator *jool)
{
	struct config_candidate *new = jool->newcfg;
	struct global_configuration *global;
	struct full_config *remnants = NULL;
	int error;

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
		if (new->nat64.bib) {
			bibdb_put(jool->nat64.bib);
			jool->nat64.bib = new->nat64.bib;
			new->nat64.bib = NULL;
		}
	}

	error = xlator_replace(jool);
	if (error) {
		log_err("xlator_replace() failed. Errcode %d", error);
		return error;
	}

	/*
	 * This the little flaw in the design.
	 * I can't make full new versions of BIB and session just over a few
	 * configuration values because the trees can be massive, so instead
	 * I'm patching values after I know the pointer swap was successful.
	 * Because they can't fail there are no dire consequences, but you know.
	 * These look a little out of place.
	 */
	if (remnants) {
		bibdb_config_set(jool->nat64.bib, &remnants->bib);
		sessiondb_config_set(jool->nat64.session, &remnants->session);
		fragdb_config_set(jool->nat64.frag, &remnants->frag);
		kfree(remnants);
	}

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

	/* TODO validate stateness. */
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
		log_err("Unknown configuration mode.") ;
		error = -EINVAL;
		break;
	}

	if (error)
		rollback(jool);

	mutex_unlock(&lock);

	return error;
}

void cfgcandidate_print_refcount(struct config_candidate *candidate)
{
	log_info("cfg candidate: %d", atomic_read(&candidate->refcount.refcount));
}
