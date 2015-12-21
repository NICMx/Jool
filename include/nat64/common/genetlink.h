#ifndef __GENETLINK_H__
#define __GENETLINK_H__

#include <linux/types.h>

#define GNL_JOOL_FAMILY_NAME "Jool"

#define GNL_JOOLD_MULTICAST_GRP_NAME "MCJoold"


enum genl_mc_group_ids {
	JOOLD_MC_ID = (1 << 0),
};


enum genl_commands {
	JOOL_COMMAND,
};


/**
 * Attributes are fields of data your messages will contain.
 * The designers of Netlink really want you to use these instead of just dumping
 * data to the packet payload... and I have really mixed feelings about it.
 */
enum attributes {
	ATTR_DUMMY,
	__ATTR_MAX,
};

struct nl_core_buffer{
	int error_code;
	bool pending_data;
	size_t len;
	size_t capacity;
};



#endif
