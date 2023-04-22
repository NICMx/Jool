#ifndef SRC_MOD_NAT64_POOL4_RFC6056_H_
#define SRC_MOD_NAT64_POOL4_RFC6056_H_

#include "common/types.h"
#include "mod/common/translation_state.h"

int rfc6056_setup(void);
void rfc6056_teardown(void);

int rfc6056_f(struct xlation *state, __u32 *entry_offset, __u32 *port_offset);

#endif /* SRC_MOD_NAT64_POOL4_RFC6056_H_ */
