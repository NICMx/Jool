#include "mod/common/nl/global.h"

#include <linux/sort.h>
#include "common/common-global.h"
#include "common/constants.h"
#include "common/types.h"
#include "mod/common/config.h"
#include "mod/common/nl/nl_common.h"
#include "mod/common/nl/nl_core2.h"
#include "mod/nat64/joold.h"
#include "mod/nat64/bib/db.h"
#include "mod/siit/eam.h"

/* TODO (NOW) transform jiffies to milliseconds in globals */

static int handle_global_display(struct xlator *jool, struct genl_info *info)
{
	struct globals config;
	bool pools_empty;

	log_debug("Returning 'Global' options.");

	memcpy(&config, &jool->global->cfg, sizeof(config));

	pools_empty = !jool->global->cfg.pool6.set;
	if (xlat_is_siit())
		pools_empty &= eamt_is_empty(jool->siit.eamt);
	prepare_config_for_userspace(&config, pools_empty);

	return nlcore_respond_struct(info, &config, sizeof(config));
}

/**
 * This consumes one global update request tuple from @request, and applies it
 * to @cfg.
 *
 * @request is assumed to be the payload of some request packet, which contains
 * a sequence of [field, value] tuples. ("field" is struct global_value and
 * "value" is the actual value, whose semantics are described by "field".)
 * Again, only one of those tuples will be consumed by this function.
 *
 * Returns
 * >= 0: Number of bytes consumed from the payload. (ie. the size of the tuple.)
 * < 0: Error code.
 */
int global_update(struct global_config *cfg, bool force,
		struct global_value *request, size_t request_size)
{
	struct global_field *field;
	unsigned int field_count;
	int error;

	if (request_size < sizeof(*request)) {
		log_err("The request is too small to contain a global_value header.");
		return -EINVAL;
	}

	/* Get the current metadata for the field we want to edit. */
	get_global_fields(&field, &field_count);

	if (request->type >= field_count) {
		log_err("Request type index %u is out of bounds.",
				request->type);
		return -EINVAL;
	}

	field = &field[request->type];

	if (xlat_is_siit() && !(field->xlator_type & XT_SIIT)) {
		log_err("Field %s is not available in SIIT.", field->name);
		return -EINVAL;
	}
	if (xlat_is_nat64() && !(field->xlator_type & XT_NAT64)) {
		log_err("Field %s is not available in NAT64.", field->name);
		return -EINVAL;
	}
	if (field->type->size > (request_size - sizeof(*request))) {
		log_err("Invalid field size. Field %s (type %s) expects %zu bytes, %zu received.",
				field->name,
				field->type->name,
				field->type->size,
				request_size - sizeof(*request));
		return -EINVAL;
	}

	error = 0;
	if (field->validate)
		error = field->validate(field, request + 1, force);
	else if (field->type->validate)
		error = field->type->validate(field, request + 1, force);
	if (error)
		return error;

	/*
	 * Replace the one field that userspace is requesting in @cfg,
	 * in a very ugly but effective way.
	 */
	memcpy(((void *)&cfg->cfg) + field->offset, request + 1,
			field->type->size);
	return sizeof(*request) + field->type->size;
}

static int handle_global_update(struct xlator *jool, struct genl_info *info,
		struct request_hdr *hdr)
{
	struct global_config *cfg;
	int error;

	log_debug("Updating 'Global' option.");

	/*
	 * This is implemented as an atomic configuration run with only a single
	 * globals modification.
	 *
	 * Why?
	 *
	 * First, I can't just modify the value directly because ongoing
	 * translations could be using it. Making those values atomic is
	 * awkward because not all of them are basic data types and atomic_t is
	 * not exported to userspace. (struct globals needs to be.)
	 *
	 * Protecting the values by a spinlock is feasible but dirty and not
	 * very performant. The translating code wants to query the globals
	 * often and I don't think that locking all the time is very healthy.
	 *
	 * remain constant through a translation, because bad things might
	 * happen if a value is queried at the beginning of the pipeline, some
	 * stuff is done based on it, and a different value pops when queried
	 * later. We could ask the code to query every value just once, but
	 * really that's not intuitive and won't sit well for new coders.
	 *
	 * So really, we don't want to edit values. We want to replace the
	 * entire structure via RCU so ongoing translations will keep their
	 * current configurations and future ones will have the new config from
	 * the beginning.
	 *
	 * Which leads to the second point: I don't want to protect
	 * xlator.globals with RCU either because I don't want to lock RCU every
	 * single time I want to query a global. Now I know that RCU-locking is
	 * faster than spin-locking, but hear me out:
	 *
	 * We could just change the entire xlator. Not only because we already
	 * need to support that for atomic configuration, but also because it
	 * literally does not impose any additional synchronization rules
	 * whatsoever for the translating code. The only overhead over replacing
	 * only xlator.globals is that we need to allocate an extra xlator
	 * during this operation. Which is not a recurrent operation at all.
	 *
	 * So let's STFU and do that.
	 */

	/* Get a clone of the current config. */
	cfg = config_alloc(&jool->global->cfg.pool6);
	if (!cfg)
		return nlcore_respond(info, -ENOMEM);
	memcpy(&cfg->cfg, &jool->global->cfg, sizeof(cfg->cfg));

	/* Perform the atomic configuration operation on our clone. */
	error = global_update(cfg, hdr->force, (struct global_value *)(hdr + 1),
			nla_len(info->attrs[ATTR_DATA]) - sizeof(*hdr));
	if (error < 0)
		return nlcore_respond(info, error);

	/*
	 * Replace the clone of the instance's old config with the new one.
	 *
	 * Notice that this @jool is also a clone and we're the only thread
	 * with access to it.
	 */
	config_put(jool->global);
	jool->global = cfg;

	/* Replace the device's official translator with the @jool clone. */
	return nlcore_respond(info, xlator_replace(jool));
}

int handle_global_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_FOREACH:
		return handle_global_display(jool, info);
	case OP_UPDATE:
		return handle_global_update(jool, info, hdr);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
