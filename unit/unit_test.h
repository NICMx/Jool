/*
 * Macros to be used by test methods.
 */
#define ASSERT_EQUALS(expected, actual, test_name) \
	if (expected != actual) { \
		printk(KERN_WARNING "Test failed: %s Expected: %d. Actual: %d.", test_name, expected, actual); \
		return -EAGAIN; \
	}

#define ASSERT_NULL(actual, test_name) \
	if (actual != NULL) { \
		printk(KERN_WARNING "Test failed: %s Expected: NULL. Actual: %d.", test_name, (int) actual); \
		return -EAGAIN; \
	}

#define END_TEST \
	return 0

/**
 * Macros to be used by the main function.
 */

#define START_TESTS(module_name)	\
	int test_counter = 0;			\
	int failure_counter = 0;		\
	printk(KERN_INFO "Module '%s': Starting tests...\n\n", module_name)

#define CALL_TEST(test, test_name)									\
	printk(KERN_INFO "Test '%s': Starting...\n", test_name);		\
	test_counter++;													\
	if (test) {														\
		printk(KERN_INFO "Test '%s': Success.\n\n", test_name);		\
	} else {														\
		printk(KERN_INFO "Test '%s': Failure.\n\n", test_name);		\
		failure_counter++;											\
	}

#define END_TESTS \
	printk(KERN_INFO "Finished. Runs: %d; Errors: %d\n", test_counter, failure_counter); \
	return 0
