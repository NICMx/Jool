#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include <linux/types.h>

int send_packet(void *pkt, __u32 pkt_len, __u8 operation);
int send_flush_op(__u8 operation);

#endif /* COMMUNICATION_H_ */
