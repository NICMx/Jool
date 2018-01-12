#ifndef _JOOL_MOD_SEND_PACKET_H
#define _JOOL_MOD_SEND_PACKET_H

/**
 * Functions to artificially send homemade packets through the interfaces.
 * Basically, you initialize sk_buffs and this worries about putting them on the
 * network.
 */

#include "packet.h"

/**
 * Puts @pkt on the network.
 *
 * Note that this function inherits from ip_local_out() and ip6_local_out() the
 * annoying side effect of freeing @pkt->skb, EVEN IF IT COULD NOT BE SENT.
 */
int sendpkt_send(struct packet *pkt);

#endif /* _JOOL_MOD_SEND_PACKET_H */
