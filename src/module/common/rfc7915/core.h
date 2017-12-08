#ifndef _JOOL_MOD_RFC6145_CORE_H
#define _JOOL_MOD_RFC6145_CORE_H

/**
 * @file
 * This is the face of the "Translating the Packet" code. Files outside of this
 * folder should only see the API exposed by this file.
 *
 * "Translating the Packet" is the core translation of SIIT and the fourth step
 * of NAT64 (RFC6146 section 3.7).
 */

#include <linux/ip.h>
#include <linux/skbuff.h>
#include "nat64/mod/common/translation_state.h"

verdict translating_the_packet(struct xlation *state);

#endif /* _JOOL_MOD_RFC6145_CORE_H */
