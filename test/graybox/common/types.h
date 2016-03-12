#ifndef _NF_NAT64_TYPES_H
#define _NF_NAT64_TYPES_H

#include <linux/types.h>

enum graybox_command {
	COMMAND_EXPECT,
	COMMAND_SEND,
	COMMAND_FLUSH,
	COMMAND_STATS,
};

enum graybox_attribute {
	ATTR_FILENAME = 1,
	ATTR_PKT,
	ATTR_EXCEPTIONS,
	ATTR_STATS,
};

struct graybox_proto_stats {
	__u32 successes;
	__u32 failures;
	__u32 queued;
};

struct graybox_stats {
	struct graybox_proto_stats ipv6;
	struct graybox_proto_stats ipv4;
};

#endif
