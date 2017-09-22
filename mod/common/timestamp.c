#include "nat64/mod/common/timestamp.h"

#include <linux/jiffies.h>
#include <linux/spinlock.h>

/*
 * Note: In this context, "wrap" means as in the sense of returning to the
 * beginning of a circular data structure.
 */

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


#define PERIOD_DURATION (60 * 1000) /** 60k msecs, aka 1 min. */

/**
 * Keep in mind that this whole thing needs to fit in a single netlink message,
 * because the copy to userspace doesn't currently bother with fragmenting it.
 *
 * Only BATCH_COUNT batches are kept in memory. Older batches get overriden, as
 * the first dimension of this is meant to be a circular array.
 * (This is fine because the userspace app is meant to request this information
 * often enough.)
 */
static struct timestamp_stat_group stats[TS_BATCH_COUNT][TST_LENGTH];
/**
 * Batch counter. It is the absolute total number of batches we've processed.
 * (Excluding the one we're currently at.)
 *
 * -1 stands for "we haven't even initialized this module".
 */
static int b = -1;
/** Jiffy at which the current batch's period started. */
static unsigned long epoch;

static DEFINE_SPINLOCK(lock);


static bool need_new_batch(void)
{
	if (b == -1)
		return true;

	return time_after(jiffies, epoch + msecs_to_jiffies(PERIOD_DURATION));
}

static int wrap(int batch)
{
	/*
	 * I know this could be "& 3", but I might need to tweak BATCH_COUNT
	 * in the future. I'm hoping gcc will realize it can optimize this.
	 */
	return batch % TS_BATCH_COUNT;
}

void TIMESTAMP_END(timestamp beginning, timestamp_type type, bool success)
{
	struct timestamp_stats *stat;
	timestamp delta = jiffies - beginning;
	int wb = wrap(b);

	spin_lock_bh(&lock);

	if (need_new_batch()) {
		b++;
		wb = wrap(b);
		memset(&stats[wb], 0, sizeof(stats[wb]));
		epoch = jiffies;
	}

	stat = success ? &stats[wb][type].successes : &stats[wb][type].failures;

	if (!stat->initialized) {
		stat->min = delta;
		stat->max = delta;
		stat->total = delta;
		stat->count = 1;
		stat->initialized = true;
		spin_unlock_bh(&lock);
		return;
	}

	if (time_before(delta, stat->min))
		stat->min = delta;
	else if (time_after(delta, stat->max))
		stat->max = delta;
	stat->total += delta;
	stat->count++;
	spin_unlock_bh(&lock);
}

static __u32 compute_avg(struct timestamp_stats *stat)
{
	return (stat->count != 0) ? (stat->total / stat->count) : 0;
}

int timestamp_foreach(struct timestamp_foreach_func *func, void *args)
{
	struct timestamp_stats *stat;
	struct timestamps_entry_usr usr;
	/*
	 * I literally have no clue what to call these variables.
	 * bb is a local batch counter (on top of the global batch counter, "b")
	 * and the latter is just the wrapped version of bb to prevent so many
	 * modulos.
	 */
	int bb, wbb;
	unsigned int s; /* Stat group counter. */
	int result = 0;

	/*
	 * Rrrrg. This sucks pretty hard. It risks increasing the experiment's
	 * averages and max's. I dunno. Try not requesting the stats too often.
	 */
	spin_lock_bh(&lock);

	for (bb = b; bb > b - TS_BATCH_COUNT && bb >= 0; bb--) {
		wbb = wrap(bb);
		for (s = 0; s < TST_LENGTH; s++) {
			stat = &stats[wbb][s].successes;
			usr.success_count = stat->count;
			usr.success_min = jiffies_to_msecs(stat->min);
			usr.success_avg = jiffies_to_msecs(compute_avg(stat));
			usr.success_max = jiffies_to_msecs(stat->max);
			stat = &stats[wbb][s].failures;
			usr.failure_count = stat->count;
			usr.failure_min = jiffies_to_msecs(stat->min);
			usr.failure_avg = jiffies_to_msecs(compute_avg(stat));
			usr.failure_max = jiffies_to_msecs(stat->max);

			result = func->cb(&usr, args);
			if (result)
				goto end;
		}
	}

end:
	spin_unlock_bh(&lock);
	return result;
}
