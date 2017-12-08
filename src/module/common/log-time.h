#ifndef _JOOL_MOD_LOG_TIME_H
#define _JOOL_MOD_LOG_TIME_H

/**
 * @file
 * Log file for benchmark purposes.
 *
 * This code is not used during normal translations; we link it only when we
 * want to measure stuff.
 */

#include "nat64/mod/common/packet.h"
#include <linux/spinlock.h>
#include <linux/time.h>

struct log_node {
	struct timespec time;
	struct list_head list_hook;
};

#ifdef BENCHMARK

void logtime(struct packet *pkt);
int logtime_iterate_and_delete(l3_protocol l3_proto, l4_protocol l4_proto,
		int (*func)(struct log_node *, void *), void *arg);
int logtime_init(void);
void logtime_destroy(void);

#else /* BENCHMARK */

#define logtime(pkt)
#define logtime_iterate_and_delete(l3_proto, l4_proto, func, arg) 0
#define logtime_init() 0
#define logtime_destroy()

#endif /* BENCHMARK */

#endif /* _JOOL_MOD_LOG_TIME_H */
