#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

#include <linux/kref.h>
#include "common/config.h"

struct global_config {
	struct globals cfg;
	struct kref refcounter;
};

struct global_config *config_alloc(struct config_prefix6 *pool6);
void config_get(struct global_config *global);
void config_put(struct global_config *global);

void config_copy(struct globals *from, struct globals *to);

#define pool6_contains(state, addr) \
	prefix6_contains(&(state)->jool.global->cfg.pool6.prefix, addr)

#endif /* _JOOL_MOD_CONFIG_H */
