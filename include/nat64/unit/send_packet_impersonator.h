#include <linux/skbuff.h>

struct sk_buff *get_sent_pkt(void);
void set_sent_pkt(struct sk_buff *skb);
