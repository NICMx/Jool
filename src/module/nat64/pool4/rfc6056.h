#ifndef _JOOL_MOD_BIB_PORT_ALLOCATOR_H
#define _JOOL_MOD_BIB_PORT_ALLOCATOR_H

#include "xlation.h"
#include "types.h"

int rfc6056_init(void);
void rfc6056_destroy(void);

int rfc6056_f(struct xlation *state, unsigned int *result);

#endif /* _JOOL_MOD_BIB_PORT_ALLOCATOR_H */
