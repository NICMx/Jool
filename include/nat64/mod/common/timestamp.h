#ifndef INCLUDE_NAT64_MOD_COMMON_TIMESTAMP_H_
#define INCLUDE_NAT64_MOD_COMMON_TIMESTAMP_H_

#include "nat64/common/config.h"

/*
 * Ehh... this should be private. Feel free to ignore it if you're reading the
 * API... --U
 */
#define TS_BATCH_COUNT 1

#if defined(TIMESTAMP_JIFFIES)

typedef unsigned long timestamp;
#define TIMESTAMP_DECLARE_START(name) timestamp name = jiffies
#define TIMESTAMP_DECLARE(name) timestamp name
#define TIMESTAMP_START(name) name = jiffies
#define TIMESTAMP_STOP(a, b, c) timestamp_stop(a, b, c)

#elif defined(TIMESTAMP_TIMESPEC)

#include <linux/time.h>
#include <linux/time64.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
typedef struct timespec64 timestamp;
#define TIMESTAMP_DECLARE_START(name) timestamp name; getnstimeofday64(&name)
#define TIMESTAMP_DECLARE(name) timestamp name
#define TIMESTAMP_START(name) getnstimeofday64(&name)
#define TIMESTAMP_STOP(a, b, c) timestamp_stop(a, b, c)

#else

#define timestamp int /* Whatevs */
#define TIMESTAMP_DECLARE_START(name) /* Empty */
#define TIMESTAMP_DECLARE(name) /* Empty */
#define TIMESTAMP_START(name) /* Empty */
#define TIMESTAMP_STOP(a, b, c) /* Empty */

#endif

void timestamp_stop(timestamp ts, timestamp_type type, bool success);

struct timestamp_foreach_func {
	int (*cb)(struct timestamps_entry_usr *, void *);
	void *arg;
};

int timestamp_foreach(struct timestamp_foreach_func *func, void *args);

#endif /* INCLUDE_NAT64_MOD_COMMON_TIMESTAMP_H_ */
