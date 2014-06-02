#include "nat64/comm/log_time.h"


/**
 * Init the struct of log_time
 */
void logtime_init(struct log_time *log_time)
{
	spin_lock_init(&log_time->lock);
	log_time->counter = 0;
	log_time->counter = 0;
}

/**
 * Increases the counter of the structure and add to the sum delta time registered.
 */
void logtime(struct log_time *log_time, unsigned long delta_time)
{
	spin_lock_bh(&log_time->lock);

	log_time->counter++;
	log_time->sum += delta_time;

	spin_unlock_bh(&log_time->lock);
}

/**
 * Prints the counter of the structure.
 *
 * The printk function is used to print, make sure to
 * print a line break after used this function.
 */
void logtime_print_counter(struct log_time *log_time)
{
	spin_lock_bh(&log_time->lock);

	printk("%u,", log_time->counter);

	spin_unlock_bh(&log_time->lock);
}

/**
 * Prints the average of the sum and multiply it by the given value,
 * useful when the time delta overflow the sum.
 *
 * The printk function is used to print, make sure to
 * print a line break after used this function.
 */
void logtime_print_avg_multiply(struct log_time *log_time, int multiplier)
{
	spin_lock_bh(&log_time->lock);

	printk("%lu,", (log_time->sum/log_time->counter)*multiplier);

	spin_unlock_bh(&log_time->lock);
}

/**
 * Prints the average of the sum.
 *
 * The printk function is used to print, make sure to
 * print a line break after used this function.
 */
void logtime_print_avg(struct log_time *log_time)
{
	spin_lock_bh(&log_time->lock);

	printk("%lu,", log_time->sum/log_time->counter);

	spin_unlock_bh(&log_time->lock);
}

/**
 * Resets the values ​​of the structure.
 */
void logtime_restart(struct log_time *log_time)
{
	spin_lock_bh(&log_time->lock);

	log_time->counter = 0;
	log_time->sum = 0;

	spin_unlock_bh(&log_time->lock);
}
