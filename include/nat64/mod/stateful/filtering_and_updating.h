#ifndef _JOOL_MOD_FILTERING_H
#define _JOOL_MOD_FILTERING_H

/**
 * @file
 * Second step of the stateful NAT64 translation algorithm: "Filtering and Updating Binding and
 * Session Information", as defined in RFC6146 section 3.5.
 *
 * @author Roberto Aceves
 * @author Alberto Leiva
 * @author Daniel Hernandez
 */

#include "nat64/mod/common/types.h"

verdict filtering_and_updating(struct sk_buff *skb, struct tuple *in_tuple);

#endif /* _JOOL_MOD_FILTERING_H */
