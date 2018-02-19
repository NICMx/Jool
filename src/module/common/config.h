#ifndef _JOOL_MOD_CONFIG_H
#define _JOOL_MOD_CONFIG_H

#include <linux/kref.h>
#include "nl-protocol.h"

struct global_config {
	struct globals cfg;
	struct kref refcounter;
};

struct global_config *config_init(xlator_type type);
void config_get(struct global_config *global);
void config_put(struct global_config *global);

#endif /* _JOOL_MOD_CONFIG_H */
