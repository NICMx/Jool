#ifndef __GENETLINK_H__
#define __GENETLINK_H__

#include <linux/types.h>
#ifndef __KERNEL__
#include <stdbool.h>
#endif

#define GNL_JOOL_FAMILY_NAME "Jool"

#define GNL_JOOLD_MULTICAST_GRP_NAME "MCJoold"


enum genl_mc_group_ids {
	JOOLD_MC_ID = (1 << 0),
};


enum genl_commands {
	JOOL_COMMAND,
};

enum attributes {
	ATTR_DUMMY,
	ATTR_DATA,
	__ATTR_MAX,
};

struct nlcore_buffer {
	__u16 payload_len;
	__u16 capacity;
	void *data;
};



#endif
