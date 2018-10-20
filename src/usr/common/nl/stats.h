#ifndef _JOOL_USR_COMMON_NL_STATS_H
#define _JOOL_USR_COMMON_NL_STATS_H

#include <linux/types.h>
#include "common/stats.h"

struct jstat_metadata {
	enum jool_stat_id id;
	char *name;
	char *doc;
};

struct jstat {
	struct jstat_metadata meta;
	__u64 value;
};

typedef int (*stats_foreach_cb)(struct jstat const *stat, void *args);
int stats_foreach(char *iname, stats_foreach_cb cb, void *args);

#endif /* _JOOL_USR_COMMON_NL_STATS_H */
