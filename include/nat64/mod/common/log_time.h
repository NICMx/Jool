#ifndef _JOOL_MOD_LOG_TIME_H
#define _JOOL_MOD_LOG_TIME_H

/**
 * @file
 * Log file for benchmark purpose.
 *
 * This code is not used during normal translations; we link it only when we want to measure stuff.
 *
 * @author Daniel Hernandez
 */

#include "nat64/mod/common/types.h"

#include <linux/spinlock.h>
#include <linux/time.h>

struct log_time_db {
	struct list_head list;
	spinlock_t lock;
};

struct log_node {
	struct timespec time;
	struct list_head list_hook;
};

/**
 * Increases the counter of the structure and add to the sum delta time registered.
 */
int logtime(struct timespec *start_time, struct timespec *end_time, l3_protocol l3_proto,
		l4_protocol l4_proto);
/**
 * Iterate over a "struct log_time_db" (which is given by the l3_protocol and l4_protocol) and
 * each iteration do the "func" call and then delete the node.
 */
int logtime_iterate_and_delete(l3_protocol l3_proto, l4_protocol l4_proto,
		int (*func)(struct log_node *, void *), void *arg);
int logtime_init(void);
void logtime_destroy(void);


#endif /* _JOOL_MOD_LOG_TIME_H */
