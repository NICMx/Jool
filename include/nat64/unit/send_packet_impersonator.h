#include <linux/skbuff.h>

struct sk_buff *get_sent_skb(void);
void set_sent_skb(struct sk_buff *skb);
