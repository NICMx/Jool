#ifndef _JOOL_USR_GLOBAL_H
#define _JOOL_USR_GLOBAL_H

#include "config.h"
#include "userspace-types.h"

int global_display(display_flags flags);
int global_update(__u16 type, size_t size, void *data);


#endif /* _JOOL_USR_GLOBAL_H */
