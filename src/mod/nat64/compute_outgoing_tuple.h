#ifndef SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_
#define SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_

/**
 * @file
 * Third step in the packet processing algorithm defined in the RFC.
 * The 3.6 section of RFC 6146 is encapsulated in this module.
 * Infers a tuple (summary) of the outgoing packet, yet to be created.
 */

#include "mod/common/translation_state.h"

verdict compute_out_tuple(struct xlation *state);

#endif /* SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_ */
