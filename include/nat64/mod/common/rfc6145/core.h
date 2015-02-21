#ifndef _JOOL_MOD_RFC6145_CORE_H
#define _JOOL_MOD_RFC6145_CORE_H

/**
 * @file
 * This is the face of the "Translating the Packet" code. Files outside of this folder should only
 * see the API exposed by this file.
 *
 * "Translating the Packet" is the fourth step of the Nat64 translation algorithm, and it's defined
 * by RFC6146 section 3.7.
 *
 * @author Alberto Leiva
 */

#include <linux/ip.h>
#include <linux/skbuff.h>
#include "nat64/mod/common/packet.h"

/**
 * Actual translation of "in" into "out".
 */
verdict translating_the_packet(struct tuple *out_tuple, struct packet *in, struct packet *out);

#endif /* _JOOL_MOD_RFC6145_CORE_H */
