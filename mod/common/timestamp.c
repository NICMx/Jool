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


#define BATCH_PERIOD (60) /* In seconds. */

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


static bool timestamps_enabled(void)
{
#if defined(TIMESTAMP_JIFFIES) || defined(TIMESTAMP_TIMESPEC)
	return true;
#else
	return false;
#endif
}

static bool need_new_batch(void)
{
	if (b == -1)
		return true;

	return time_after(jiffies,
			epoch + msecs_to_jiffies(BATCH_PERIOD * 1000));
}

static int wrap(int batch)
{
	/*
	 * I know this could be "& 3", but I might need to tweak BATCH_COUNT
	 * in the future. I'm hoping gcc will realize it can optimize this.
	 */
	return batch % TS_BATCH_COUNT;
}

#if defined(TIMESTAMP_JIFFIES)

/**
 * Returns the time difference between now and beginning.
 */
static timestamp compute_delta(timestamp beginning)
{
	return jiffies - beginning;
}

/*
 * lhs < rhs:  return <0
 * lhs == rhs: return 0
 * lhs > rhs:  return >0
 */
static int timestamp_compare(timestamp *lhs, timestamp *rhs)
{
	return (*lhs) - (*rhs);
}

static timestamp timestamp_add(timestamp t1, timestamp t2)
{
	return t1 + t2;
}

#elif defined(TIMESTAMP_TIMESPEC)

static timestamp compute_delta(timestamp beginning)
{
	timestamp now;
	getnstimeofday64(&now);
	return timespec64_sub(now, beginning);
}

static int timestamp_compare(timestamp *lhs, timestamp *rhs)
{
	return timespec_compare(lhs, rhs);
}

static timestamp timestamp_add(timestamp lhs, timestamp rhs)
{
	return timespec_add(lhs, rhs);
}

#else

#define compute_delta(a) 0
#define timestamp_compare(a, b) 0
#define timestamp_add(a, b) 0

#endif

/**
 * The reason why the first argument is a struct and not a pointer is because
 * I'm following along with the timespec's API's idiosyncrasies. It's weird.
 */
void timestamp_stop(timestamp beginning, timestamp_type type, bool success)
{
	struct timestamp_stats *stat;
	timestamp delta;
	int wb;

	if (WARN(!timestamps_enabled(), "Timestamps feature disabled but someone called a timestamps function."))
		return;

	delta = compute_delta(beginning);
	wb = wrap(b);

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

	if (timestamp_compare(&delta, &stat->min) < 0)
		stat->min = delta;
	else if (timestamp_compare(&delta, &stat->max) > 0)
		stat->max = delta;
	stat->total = timestamp_add(stat->total, delta);
	stat->count++;
	spin_unlock_bh(&lock);
}

#if defined(TIMESTAMP_JIFFIES)

/**
 * Not sure if this name is self-explanatory. Think of "cap" as in like a Fire
 * Emblem stat "cap".
 */
static __u32 cap_u32(unsigned int number)
{
	return (number > U32_MAX) ? U32_MAX : number;
}

static __u32 tstou32(timestamp *ts)
{
	return cap_u32(jiffies_to_msecs(*ts));
}

static __u32 compute_avg(struct timestamp_stats *stat)
{
	if (stat->count == 0)
		return 0;
	return cap_u32(jiffies_to_msecs(stat->total / stat->count));
}

#elif defined(TIMESTAMP_TIMESPEC)

static __u32 cap_u32(__u64 number)
{
	return (number > U32_MAX) ? U32_MAX : number;
}

static __u64 get_total_microseconds(timestamp *ts)
{
	__u64 micros = 0;

	micros += ((__u64)1000000) * (__u64)ts->tv_sec;
	micros += ts->tv_nsec / 1000;

	return micros;
}

/**
 * AFAIK, even though timespecs have a nanosecond field, the precision is far
 * lower than that due to both hardware and software constraints.
 * Also, we don't have all that much room in a __u32, so I'm going to convert
 * them to microseconds.
 */
static __u32 tstou32(timestamp *ts)
{
	return cap_u32(get_total_microseconds(ts));
}

static __u32 compute_avg(struct timestamp_stats *stat)
{
	if (stat->count == 0)
		return 0;
	return cap_u32(get_total_microseconds(&stat->total) / stat->count);
}

#else

#define tstou32(a) 0
#define compute_avg(a) 0

#endif

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

	if (!timestamps_enabled()) {
		log_err("This binary was not compiled to support timestamps.");
		return -EINVAL;
	}

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
			usr.success_min = tstou32(&stat->min);
			usr.success_avg = compute_avg(stat);
			usr.success_max = tstou32(&stat->max);
			stat = &stats[wbb][s].failures;
			usr.failure_count = stat->count;
			usr.failure_min = tstou32(&stat->min);
			usr.failure_avg = compute_avg(stat);
			usr.failure_max = tstou32(&stat->max);

			result = func->cb(&usr, args);
			if (result)
				goto end;
		}
	}

end:
	spin_unlock_bh(&lock);
	return result;
}
