#ifndef COMMUNICATION_H_
#define COMMUNICATION_H_

#include "types.h"
#include "netlink.h"


int send_packet(void *pkt, __u32 pkt_len, char *filename, __u32 str_len, enum config_mode mode,
		enum config_operation op);

int send_flush_op(enum config_mode mode, enum config_operation op);

int global_update(__u8 type, size_t size, void *data);

int general_display_array(void);

int receiver_display(void);


#endif /* COMMUNICATION_H_ */
