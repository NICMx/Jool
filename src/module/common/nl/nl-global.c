#include "nl/nl-global.h"

#include "common-global.h"
#include "constants.h"
#include "types.h"
#include "config.h"
#include "nl/nl-common.h"
#include "nl/nl-core.h"
#include "nat64/joold.h"
#include "nat64/bib/db.h"
#include "siit/eam.h"

static int handle_global_display(struct xlator *jool, struct genl_info *info)
{
	struct globals clone;

	log_debug("Returning 'Global' options.");

	memcpy(&clone, &jool->global->cfg, sizeof(clone));
	prepare_config_for_userspace(&clone);
	return nlcore_respond_struct(info, &clone, sizeof(clone));
}

static char *get_instance_name(struct genl_info *info)
{
	struct nlattr *name;

	name = info->attrs[ATTR_INSTANCE_NAME];
	if (WARN(!name, "The request lacks an instance name attribute despite validations."))
		return NULL;

	return nla_data(name);
}

static int handle_global_update(struct xlator *jool, struct genl_info *info)
{
	struct request_global_update *request = get_jool_payload(info);
	struct global_field *field;
	unsigned int field_count;
	struct global_config *cfg;
	char *name;

	if (verify_privileges())
		return nlcore_respond(info, -EPERM);

	log_debug("Updating 'Global' options.");

	/*
	 * This is implemented as an atomic configuration run with only a single
	 * globals modification.
	 *
	 * Why?
	 *
	 * First, I can't just modify the value directly because ongoing
	 * translations could be using it. Making those values atomic is
	 * awkward because not all of them are basic data types and atomic_t is
	 * not exported to userspace. (struct full_config needs to be.)
	 *
	 * Protecting the values by a spinlock is feasible but dirty and not
	 * very performant. The translating code wants to query the globals
	 * often and I don't think that locking all the time is very healthy.
	 *
	 * There's also the point of consistency. It's better if the globals
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
	cfg = config_init(jool->global->cfg.xlator_type);
	if (!cfg)
		return nlcore_respond(info, -ENOMEM);
	memcpy(&cfg, &jool->global->cfg, sizeof(cfg));

	/* Get the current metadata for the field we want to edit. */
	get_global_fields(&field, &field_count);

	if (request->type >= field_count) {
		log_err("Request type index %u is out of bounds.", request->type);
		return nlcore_respond(info, -EINVAL);
	}

	field = &field[request->type];

	if (nla_len(info->attrs[ATTR_DATA]) != sizeof(*request) + field->type->size) {
		log_err("Invalid field size. Field %s (type %s) expects %zu bytes, %zu received.",
				field->name, field->type->name, field->type->size,
				nla_len(info->attrs[ATTR_DATA]) - sizeof(*request));
		return nlcore_respond(info, -EINVAL);
	}

	/*
	 * Replace the one field that userspace is requesting in our clone
	 * config, in a very ugly (but effective) way.
	 */
	memcpy(((void *)&cfg) + field->offset, request + 1, field->type->size);

	/*
	 * Replace the clone of the instance's old config with the new one.
	 *
	 * Notice that this "jool" is also a clone and we're the only thread
	 * with access to it.
	 */
	config_put(jool->global); /* TODO review krefs */
	jool->global = cfg;

	/* Replace the device's official translator with the "jool" clone. */
	name = get_instance_name(info);
	if (!name)
		return nlcore_respond(info, -EINVAL);
	return nlcore_respond(info, xlator_replace(name, jool));
}

int handle_global_config(struct xlator *jool, struct genl_info *info)
{
	struct request_hdr *hdr = get_jool_hdr(info);

	switch (be16_to_cpu(hdr->operation)) {
	case OP_FOREACH:
		return handle_global_display(jool, info);
	case OP_UPDATE:
		return handle_global_update(jool, info);
	}

	log_err("Unknown operation: %u", be16_to_cpu(hdr->operation));
	return nlcore_respond(info, -EINVAL);
}
