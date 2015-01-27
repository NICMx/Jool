/*
 * log_time_test.c
 *
 *  Created on: Oct 13, 2014
 *      Author: dhernandez
 */

#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/printk.h> /* pr_* */
#include <linux/time.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dhernandez");
MODULE_DESCRIPTION("Unit tests for the log_time_module");
MODULE_ALIAS("nat64_test_log_time");

#include "nat64/common/str_utils.h"
#include "nat64/unit/types.h"
#include "nat64/unit/unit_test.h"
#include "log_time.c"

static bool init(void)
{
	int error;

	error = logtime_init();
	if (error)
		goto fail;

	return true;

fail:
	return false;
}

static void end(void)
{
	logtime_destroy();
}

static bool simple_substraction(void)
{
	bool result = true;
	struct timespec start;
	struct timespec end;
	struct log_node *node;

	logtime_create_node(&node);
	if (!node)
		return false;

	start.tv_sec = 1L;
	start.tv_nsec = 999999999L;
	end.tv_sec = 2L;
	end.tv_nsec = 0L;

	subtract_timespec(&start, &end, node);
	result &= assert_equals_u64(0, node->time.tv_sec, "node tv_sec");
	result &= assert_equals_u64(1, node->time.tv_nsec, "node tv_nsec");

	logtime_delete_node(node);
	return result;
}

static int logtime_test_init(void)
{
	START_TESTS("Log time test");

	INIT_CALL_END(init(), simple_substraction(), end(), "test_log_time substraction 1");

	END_TESTS;
}

static void logtime_test_exit(void)
{
	/* No code. */
}

module_init(logtime_test_init);
module_exit(logtime_test_exit);
