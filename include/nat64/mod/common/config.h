#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

#include <linux/kref.h>
#include "nat64/common/config.h"
#include "nat64/common/types.h"

/*
 * TODO maybe this should be called "global_config" and "global_config" should
 * be called "global_config_usr".
 */
struct global_configuration {
	/* TODO rename as "values" or something */
	struct global_config cfg;
	struct kref refcounter;
};

int config_init(struct global_configuration **global, bool disable);
void config_get(struct global_configuration *global);
void config_put(struct global_configuration *global);

int config_clone(struct global_configuration *from, struct global_configuration **to);

#endif /* _JOOL_MOD_CONFIG_H */
