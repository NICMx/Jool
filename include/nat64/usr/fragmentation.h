#ifndef _FRAGMENTATION_H
#define _FRAGMENTATION_H

#include <linux/types.h>
#include "nat64/comm/config_proto.h"


#define FRAGMENTATION_TIMEOUT_OPT 	"toFragMin"

int fragmentation_request(__u32 operation, struct fragmentation_config *config);


#endif /* _FRAGMENTATION_H */

