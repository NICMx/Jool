#include "nat64/mod/common/timestamp.h"

#include <linux/jiffies.h>
#include <linux/spinlock.h>

struct timestamp_stats {
	timestamp min;
	timestamp max;

	/* These two are intended for the computation of the average later. */
	timestamp total;
	unsigned int count;

	bool initialized;
};

struct timestamp_stat_group {
	struct timestamp_stats successes;
	struct timestamp_stats failures;
};

static struct timestamp_stat_group stats[TST_LENGTH] = { 0 };
DEFINE_SPINLOCK(lock);

void TIMESTAMP_END(timestamp beginning, timestamp_type type, bool success)
{
	struct timestamp_stats *stat;
	timestamp delta = jiffies - beginning;

	stat = success ? &stats[type].successes : &stats[type].failures;

	spin_lock_bh(&lock);

	if (!stat->initialized) {
		stat->min = delta;
		stat->max = delta;
		stat->total = delta;
		stat->count = 1;
		stat->initialized = true;
		spin_unlock_bh(&lock);
		log_info("init'd.");
		return;
	}

	if (time_before(delta, stat->min))
		stat->min = delta;
	else if (time_after(delta, stat->max))
		stat->max = delta;
	stat->total += delta;
	stat->count++;
	spin_unlock_bh(&lock);

	log_info("moared.");
}

int timestamp_foreach(struct timestamp_foreach_func *func, void *args)
{
	struct timestamp_stats *stat;
	struct timestamps_entry_usr usr;
	unsigned int i;
	int quit;

	for (i = 0; i < TST_LENGTH; i++) {

		spin_lock_bh(&lock);
		stat = &stats[i].successes;
		usr.success_count = stat->count;
		usr.success_min = stat->min;
		usr.success_avg = (stat->count != 0)
				? (stat->total / stat->count)
				: 0;
		usr.success_max = stat->max;
		stat = &stats[i].failures;
		usr.failure_count = stat->count;
		usr.failure_min = stat->min;
		usr.failure_avg = (stat->count != 0)
				? (stat->total / stat->count)
				: 0;
		usr.failure_max = stat->max;
		spin_unlock_bh(&lock);

		usr.success_min = jiffies_to_msecs(usr.success_min);
		usr.success_avg = jiffies_to_msecs(usr.success_avg);
		usr.success_max = jiffies_to_msecs(usr.success_max);
		usr.failure_min = jiffies_to_msecs(usr.failure_min);
		usr.failure_avg = jiffies_to_msecs(usr.failure_avg);
		usr.failure_max = jiffies_to_msecs(usr.failure_max);

		quit = func->cb(&usr, args);
		if (quit)
			return quit;
	}

	return 0;
}
