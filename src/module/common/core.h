#ifndef _JOOL_MOD_CORE_H
#define _JOOL_MOD_CORE_H

/**
 * @file
 * The core is the packet handling's entry point.
 */

#include "translation-state.h"

verdict core_6to4(struct xlation *state, struct sk_buff *skb);
verdict core_4to6(struct xlation *state, struct sk_buff *skb);

#endif /* _JOOL_MOD_CORE_H */
