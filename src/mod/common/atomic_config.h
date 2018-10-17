#ifndef _JOOL_MOD_ATOMIC_CONFIG_H
#define _JOOL_MOD_ATOMIC_CONFIG_H

#include <linux/types.h>

int atomconfig_add(char *iname, void *config, size_t config_len, bool force);

#endif /* _JOOL_MOD_ATOMIC_CONFIG_H */
