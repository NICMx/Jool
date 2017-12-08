#ifndef _JOOL_MOD_INCOMING_H
#define _JOOL_MOD_INCOMING_H

/**
 * @file
 * The first step in the packet processing algorithm defined in the RFC.
 * The 3.4 section of RFC 6146 is encapsulated in this module.
 * Creates a tuple (summary) of the incoming packet.
 */

#include "nat64/mod/common/translation_state.h"

verdict determine_in_tuple(struct xlation *state);


#endif /* _JOOL_MOD_INCOMING_H */
