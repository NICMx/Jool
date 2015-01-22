#ifndef FRAGS_MOD_RECEIVER_H
#define FRAGS_MOD_RECEIVER_H

/**
 * @file
 * Receiver module that compare incoming packets from the network.
 *
 * @author Daniel Hdz Felix
 */


#include <linux/skbuff.h>
#include <linux/list.h>

int handle_skb_from_user(struct sk_buff *skb);

unsigned int receiver_incoming_skb4(struct sk_buff *skb);
unsigned int receiver_incoming_skb6(struct sk_buff *skb);
int receiver_flush_db(void);
int receiver_init(void);
void receiver_destroy(void);
int receiver_display_stats(void);

#endif /* FRAGS_MOD_RECEIVER_H */
