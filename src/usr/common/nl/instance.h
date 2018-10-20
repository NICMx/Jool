#ifndef _JOOL_USR_INSTANCE_H
#define _JOOL_USR_INSTANCE_H

#include "common/config.h"

typedef int (*instance_foreach_entry)(struct instance_entry_usr *instance,
		void *arg);

int instance_foreach(char *iname, instance_foreach_entry cb, void *args);
int instance_add(jframework fw, char *iname, struct ipv6_prefix *pool6);
int instance_rm(char *iname);
int instance_flush(void);

#endif /* _JOOL_USR_INSTANCE_H */
