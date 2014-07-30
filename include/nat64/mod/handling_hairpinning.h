#ifndef _JOOL_MOD_HARPINNING_H
#define _JOOL_MOD_HARPINNING_H

/**
 * @file
 * Fifth and (officially) last step of the Nat64 translation algorithm: "Handling Hairpinning", as
 * defined in RFC6146 section 3.8.
 * Recognizes a packet that should return from the same interface and handles it accordingly.
 *
 * @author Miguel Gonzalez
 * @author Alberto Leiva
 */

#include "nat64/mod/types.h"
#include "nat64/mod/packet.h"


bool is_hairpin(struct sk_buff *skb);
verdict handling_hairpinning(struct sk_buff *skb_in, struct tuple *tuple_in);


#endif /* _JOOL_MOD_HARPINNING_H */
