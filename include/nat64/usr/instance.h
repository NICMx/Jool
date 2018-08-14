#ifndef _JOOL_USR_INSTANCE_H
#define _JOOL_USR_INSTANCE_H

#include "nat64/usr/types.h"

int instance_display(display_flags flags);
int instance_add(int type, char *iname);
int instance_rm(int type, char *iname);

#endif /* _JOOL_USR_INSTANCE_H */
