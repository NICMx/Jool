#ifndef _FILTERING_H
#define _FILTERING_H

#include <linux/types.h>
#include "nat64/comm/config_proto.h"


#define DROP_BY_ADDR_OPT		"dropAddr"
#define DROP_ICMP6_INFO_OPT		"dropInfo"
#define DROP_EXTERNAL_TCP_OPT	"dropTCP"
#define UDP_TIMEOUT_OPT			"toUDP"
#define ICMP_TIMEOUT_OPT		"toICMP"
#define TCP_EST_TIMEOUT_OPT		"toTCPest"
#define TCP_TRANS_TIMEOUT_OPT 	"toTCPtrans"

int filtering_request(__u32 operation, struct filtering_config *config);


#endif /* _FILTERING_H */
