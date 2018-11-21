#ifndef _JOOL_MOD_LOG_H
#define _JOOL_MOD_LOG_H

/*
 * Why include kernel.h? because printk.h depends on it in some old kernels.
 * (3.2-3.9 it seems.)
 */
#include <linux/kernel.h>
#include <linux/printk.h>
#include "common/xlat.h"
#include "mod/common/error_pool.h"

/**
 * Messages to help us walk through a run. Also covers normal packet drops
 * (bad checksums, bogus addresses, etc) and some failed memory allocations
 * (because the kernel already prints those).
 */
#define log_debug(text, ...) \
	pr_debug("%s: " text "\n", xlat_get_name(), ##__VA_ARGS__)
/**
 * Responses to events triggered by the user, which might not show signs of life
 * elsehow.
 */
#define log_info(text, ...) \
	pr_info("%s: " text "\n", xlat_get_name(), ##__VA_ARGS__)
/**
 * Warnings. Only use this one during module insertion/deletion.
 * Elsewhere use @log_warn_once.
 */
#define log_warn(text, ...) \
	pr_warn("%s WARNING (%s): " text "\n", xlat_get_name(), __func__, \
			##__VA_ARGS__)
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
			log_warn(text, ##__VA_ARGS__); \
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
/**
 * Used when a developer wants to print a debug message, but this message would
 * not be useful after the bug is fixed. These are separated from `log_debug`
 * and `log_info` so you can spot them through simple greps and delete them
 * guilt-free.
 *
 * These should not be committed, so if you see one in uploaded code, delete it.
 */
#define log_delete(text, ...) pr_err("DELETE ME! %s(%d): " text "\n", \
		__func__, __LINE__, ##__VA_ARGS__)

#ifdef UNIT_TESTING
#undef log_err
#define log_err(text, ...) pr_err("%s ERROR (%s): " text "\n", \
		xlat_get_name(), __func__, ##__VA_ARGS__)
#endif

#define PR_DEBUG pr_err("%s:%d (%s())\n", __FILE__, __LINE__, __func__)

#endif /* _JOOL_MOD_LOG_H */
