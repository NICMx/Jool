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

/**
 * Caller writes on the buffer. Once the buffer is full or the caller finishes
 * writing, the buffer is written into an skb and fetched.
 *
 * The caller does not work on the skb directly because:
 *
 * Rob had trouble making Generic Netlink work without attributes. It might be
 * impossible. We do not want to fetch attributes because we do not have any
 * warranty they will work the same in a different Linux kernel (which is
 * relevant in joold's case - the two NAT64s can be running in different
 * kernels). So what we did is use a single binary attribute. Userspace joold
 * unwraps the attribute and sends the binary data as is. The joold on the other
 * side should parse the data correctly because it is reasonable to expect
 * Jool's version to be the same.
 *
 * TODO did we include the magic number and module version in that message?
 *
 * The problem with that is the binary blob needs to be ready by the time the
 * attribute is written into the packet. This is never the case for responses
 * to --display. In fact, it is also not true for joold.
 *
 * So we use a buffer to build the attribute content first and write the
 * attribute later.
 *
 * TODO (later) maybe find a way to do this without attributes?
 */
struct nlcore_buffer {
	__u16 len;
	__u16 capacity;
	void *data;
};


#endif
