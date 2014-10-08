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

#include <linux/skbuff.h>
#include <linux/ip.h>
#include "nat64/mod/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/packet.h"

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
 * Copies this module's current configuration to "clone".
 *
 * @param[out] clone a copy of the current config will be placed here. Must be already allocated.
 * @return zero on success, nonzero on failure.
 */
int translate_clone_config(struct translate_config *clone);
/**
 * Updates the configuration value of this module whose identifier is "type".
 *
 * @param type ID of the configuration value you want to edit.
 * @size length of "value" in bytes.
 * @value the new value you want the field to have.
 */
int translate_set_config(enum translate_type type, size_t size, void *value);

/**
 * Actual translation of "in" into "out".
 *
 * Warning: if the translated packet is too big and the situation demands it (IPv4 to IPv6 and no
 * DF), "output" will be fragmented. Its pieces will be queued in order in (*output)->next.
 * Keep that in mind when you release or send "output".
 */
verdict translating_the_packet(struct tuple *out_tuple, struct sk_buff *in,
		struct sk_buff **output);

#endif /* _JOOL_MOD_TRANSLATING_THE_PACKET_H */
