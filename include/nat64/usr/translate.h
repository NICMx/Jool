#ifndef _JOOL_USR_TRANSLATE_H
#define _JOOL_USR_TRANSLATE_H

#include <linux/types.h>
#include "nat64/comm/config_proto.h"


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

int translate_request(__u32 operation, struct translate_config *config);


#endif /* _JOOL_USR_TRANSLATE_H */
