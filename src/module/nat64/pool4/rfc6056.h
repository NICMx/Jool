#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "nat64/common/types.h"
#include "nat64/mod/common/translation_state.h"

int rfc6056_init(void);
void rfc6056_destroy(void);

int rfc6056_f(const struct tuple *tuple6, __u8 fields, unsigned int *result);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
