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

#include "nat64/mod/common/packet.h"


bool is_hairpin(struct tuple *tuple);
verdict handling_hairpinning(struct packet *pkt, struct tuple *tuple_in);


#endif /* _JOOL_MOD_HARPINNING_H */
