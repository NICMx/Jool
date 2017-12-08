#ifndef _JOOL_MOD_LOG_H
#define _JOOL_MOD_LOG_H

/*
 * Why include kernel.h? because printk.h depends on it in some old kernels.
 * (3.2-3.9 it seems.)
 */
#include <linux/kernel.h>
#include <linux/printk.h>
#include "nat64/common/xlat.h"
#include "nat64/mod/common/error_pool.h"

/**
 * Messages to help us walk through a run. Also covers normal packet drops
 * (bad checksums, bogus addresses, etc) and some failed memory allocations
 * (because the kernel already prints those).
 */
#define log_debug(text, ...) pr_debug("%s: " text "\n", xlat_get_name(), ##__VA_ARGS__)
/**
 * Responses to events triggered by the user, which might not show signs of life
 * elsehow.
 */
#define log_info(text, ...) pr_info("%s: " text "\n", xlat_get_name(), ##__VA_ARGS__)
/**
 * "I'm not going to translate this because the config's not right."
 * These rate limit themselves so the log doesn't get too flooded.
 */
#define log_warn_once(text, ...) \
	do { \
		static bool __logged = false; \
		static unsigned long __last_log; \
		\
		if (!__logged || __last_log < jiffies - msecs_to_jiffies(60 * 1000)) { \
			pr_warn("%s WARNING (%s): " text "\n", \
					xlat_get_name(), __func__, \
					##__VA_ARGS__); \
			__logged = true; \
			__last_log = jiffies; \
		} \
	} while (0)
/**
 * "Your configuration cannot be applied, user."
 * log_warn_once() signals errors while processing packets. log_err() signals
 * errors while processing user requests.
 * I the code found a **programming** error, use WARN() or its variations
 * instead.
 */
#define log_err(text, ...) \
	do { \
		char __error_message[512]; \
		pr_err("%s ERROR (%s): " text "\n", xlat_get_name(), __func__, \
				##__VA_ARGS__); \
		sprintf(__error_message, text "\n", ##__VA_ARGS__); \
		error_pool_add_message(__error_message); \
	} while (0)

#ifdef UNIT_TESTING
#undef log_err
#define log_err(text, ...) pr_err("%s ERROR (%s): " text "\n", \
		xlat_get_name(), __func__, ##__VA_ARGS__)
#endif

#endif /* _JOOL_MOD_LOG_H */
