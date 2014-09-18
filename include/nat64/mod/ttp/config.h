#ifndef _JOOL_MOD_TTP_CONFIG_H
#define _JOOL_MOD_TTP_CONFIG_H

#include "nat64/comm/config_proto.h"

int ttpconfig_init(void);
void ttpconfig_destroy(void);

int ttpconfig_clone(struct translate_config *clone);
int ttpconfig_update(enum translate_type type, size_t size, void *value);

struct translate_config *ttpconfig_get(void);

#endif /* _JOOL_MOD_TTP_CONFIG_H */
