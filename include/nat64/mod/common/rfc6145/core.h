#ifndef _JOOL_MOD_TRANSLATING_THE_PACKET_H
#define _JOOL_MOD_TRANSLATING_THE_PACKET_H

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
#include "nat64/mod/common/types.h"

/**
 * Prepares this module for future use. Avoid calling the rest of the functions unless this has
 * already been executed once.
 */
int translate_packet_init(void);
/**
 * Frees any memory allocated by this module.
 */
void translate_packet_destroy(void);

/**
 * Actual translation of "in" into "out".
 */
verdict translating_the_packet(struct tuple *out_tuple, struct sk_buff *in,
		struct sk_buff **output);

#endif /* _JOOL_MOD_TRANSLATING_THE_PACKET_H */
