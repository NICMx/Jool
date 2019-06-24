#ifndef SRC_USR_NL_STATS_H_
#define SRC_USR_NL_STATS_H_

#include "common/stats.h"
#include "jool_socket.h"

struct jstat_metadata {
	enum jool_stat_id id;
	char *name;
	char *doc;
};

struct jstat {
	struct jstat_metadata meta;
	__u64 value;
};

typedef struct jool_result (*stats_foreach_cb)(struct jstat const *stat,
		void *args);
struct jool_result stats_foreach(struct jool_socket *sk, char *iname,
		stats_foreach_cb cb, void *args);

#endif /* SRC_USR_NL_STATS_H_ */
