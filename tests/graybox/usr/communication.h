#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include "types.h"

int send_packet(void *pkt, __u32 pkt_len, enum operations op);
int send_flush_op(void);

#endif /* COMMUNICATION_H_ */
