#ifndef _JOOL_MOD_HARPINNING_H
#define _JOOL_MOD_HARPINNING_H

/**
 * @file
 * Fifth and (officially) last step of the NAT64 translation algorithm:
 * "Handling Hairpinning", as defined in RFC6146 section 3.8.
 * Recognizes a packet that should return from the same interface and handles it
 * accordingly.
 */

#include "xlation.h"

bool is_hairpin(struct xlation *state);
int handling_hairpinning(struct xlation *state);

#endif /* _JOOL_MOD_HARPINNING_H */
