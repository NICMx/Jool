#ifndef __GENETLINK_H__
#define __GENETLINK_H__

#include <linux/types.h>


#define GNL_JOOL_FAMILY_NAME (xlat_is_siit() ? "SIIT_Jool" : "NAT64_Jool")
#define GNL_JOOLD_MULTICAST_GRP_NAME "joold"


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
