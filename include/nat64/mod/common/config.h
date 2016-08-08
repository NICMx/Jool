#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

#include <linux/kref.h>
#include "nat64/common/config.h"

struct global_config {
	struct global_config_usr cfg;
	struct kref refcounter;
};

int config_init(struct global_config **global);
void config_get(struct global_config *global);
void config_put(struct global_config *global);

void config_copy(struct global_config_usr *from, struct global_config_usr *to);

#endif /* _JOOL_MOD_CONFIG_H */
