#ifndef _JOOL_USR_GENERAL_H
#define _JOOL_USR_GENERAL_H


#include "nat64/comm/config_proto.h"


#define DROP_BY_ADDR_OPT		"dropAddr"
#define DROP_ICMP6_INFO_OPT		"dropInfo"
#define DROP_EXTERNAL_TCP_OPT	"dropTCP"
#define UDP_TIMEOUT_OPT			"toUDP"
#define ICMP_TIMEOUT_OPT		"toICMP"
#define TCP_EST_TIMEOUT_OPT		"toTCPest"
#define TCP_TRANS_TIMEOUT_OPT 	"toTCPtrans"

#define RESET_TCLASS_OPT		"setTC"
#define RESET_TOS_OPT			"setTOS"
#define NEW_TOS_OPT				"TOS"
#define DF_ALWAYS_ON_OPT		"setDF"
#define BUILD_IPV4_ID_OPT		"genID"
#define LOWER_MTU_FAIL_OPT		"boostMTU"
#define IPV6_NEXTHOP_MTU_OPT	"nextMTU6"
#define IPV4_NEXTHOP_MTU_OPT	"nextMTU4"
#define MTU_PLATEAUS_OPT		"plateaus"
#define MIN_IPV6_MTU_OPT		"minMTU6"


int general_display(void);
int general_update(enum general_module module, __u8 type, size_t size, void *data);


#endif /* _JOOL_USR_GENERAL_H */
