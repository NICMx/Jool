#ifndef SRC_MOD_COMMON_LOG_H_
#define SRC_MOD_COMMON_LOG_H_

#include <linux/printk.h>

struct xlation;
struct xlator;

void JOOL_LOG(struct xlation const *state, char const *format, ...);
void __JOOL_LOG(struct xlator const *jool, char const *format, ...);
void ____JOOL_LOG(bool conditional, char const *format, ...);

#define LOGGIFY(text) KERN_INFO "Jool: " text "\n"

/**
 * Messages to help us walk through a run. Also covers normal packet drops
 * (because users catch those from stats instead) and some failed memory
 * allocations (because the kernel already prints those).
 */
#define     log_debug(state, text, ...) \
	    JOOL_LOG(state, LOGGIFY(text), ##__VA_ARGS__)
#define   __log_debug(jool,  text, ...) \
	  __JOOL_LOG(jool,  LOGGIFY(text), ##__VA_ARGS__)
#define ____log_debug(cond,  text, ...) \
	____JOOL_LOG(cond,  LOGGIFY(text), ##__VA_ARGS__)

/*
 * Debug messages not associated with an instance. They need JOOL_FLAGS=-DDEBUG.
 * I think this is fine for now; people normally wants debug messages to learn
 * why an instance is misbehaving.
 */
#define LOG_DEBUG(text, ...) \
	pr_debug("Jool: " text "\n", ##__VA_ARGS__)

/**
 * Responses to events triggered by the user, which might not show signs of life
 * elsehow.
 */
#define log_info(text, ...) \
	pr_info("Jool: " text "\n", ##__VA_ARGS__)

/**
 * Warnings. Only use this one during module insertion/deletion.
 * Elsewhere use @log_warn_once.
 */
#define log_warn(text, ...) \
	pr_warn("Jool WARNING (%s): " text "\n", __func__, ##__VA_ARGS__)

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
#ifdef UNIT_TESTING
#define log_err(text, ...) \
	pr_err("Jool ERROR (%s): " text "\n", __func__, ##__VA_ARGS__)
#else
void log_err(const char *format, ...) __attribute__((format(printf, 1, 2)));
#endif

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
#define PR_DEBUG pr_err("%s:%d (%s())\n", __FILE__, __LINE__, __func__)

#endif /* SRC_MOD_COMMON_LOG_H_ */
