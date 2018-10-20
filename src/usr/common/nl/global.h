#ifndef _JOOL_USR_GLOBAL_H
#define _JOOL_USR_GLOBAL_H

#include "common/common-global.h"
#include "common/config.h"

int global_query(char *iname, struct globals *result);
int global_update(char *iname, struct global_field *field, void *value,
		bool force);


#endif /* _JOOL_USR_GLOBAL_H */
