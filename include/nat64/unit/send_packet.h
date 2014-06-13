#ifndef _JOOL_UNIT_SEND_PKT_H
#define _JOOL_UNIT_SEND_PKT_H

#include "nat64/mod/send_packet.h"


struct sk_buff *get_sent_skb(void);
void set_sent_skb(struct sk_buff *skb);


#endif /* _JOOL_UNIT_SEND_PKT_H */
