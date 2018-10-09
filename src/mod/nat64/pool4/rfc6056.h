#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "common/types.h"
#include "mod/common/translation_state.h"

int rfc6056_setup(void);
void rfc6056_teardown(void);

int rfc6056_f(const struct tuple *tuple6, __u8 fields, unsigned int *result);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
