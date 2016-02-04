#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

#include <linux/kref.h>
#include "nat64/common/config.h"

/*
 * TODO (final) maybe this should be called "global_config" and "global_config"
 * should be called "global_config_usr".
 */
struct global_configuration {
	struct global_config cfg;
	struct kref refcounter;
};

int config_init(struct global_configuration **global, bool disable);
void config_get(struct global_configuration *global);
void config_put(struct global_configuration *global);

void config_copy(struct global_config *from, struct global_config *to);

#endif /* _JOOL_MOD_CONFIG_H */
