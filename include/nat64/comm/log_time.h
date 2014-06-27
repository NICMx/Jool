#ifndef _JOOL_COMM_LOG_TIME_H
#define _JOOL_COMM_LOG_TIME_H

/**
 * @file
 * Log file for benchmark purpose.
 *
 * @author Daniel Hernandez
 */

#include <linux/spinlock.h>

struct log_time {
	unsigned long sum;
	unsigned int counter;
	spinlock_t lock;
};

void logtime_init(struct log_time *log_time);
void logtime(struct log_time *log_time, unsigned long delta_time);
void logtime_print_avg(struct log_time *log_time);
void logtime_print_avg_multiply(struct log_time *log_time, int multiplier);
void logtime_print_counter(struct log_time *log_time);
void logtime_restart(struct log_time *log_time);


#endif /* _JOOL_COMM_LOG_TIME_H */
