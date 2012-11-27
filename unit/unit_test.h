/*
 * Macros to be used by test methods.
 */

#define ASSERT_AUX(expected, actual, printable_expected, printable_actual, specifier, test_name) \
	if ((expected) != (actual)) { \
		printk(KERN_WARNING "Test failed: %s Expected: " specifier ". Actual: " specifier ".", \
				test_name, printable_expected, printable_actual); \
		return false; \
	}

#define ASSERT_EQUALS(expected, actual, test_name) \
	ASSERT_AUX(expected, actual, expected, actual, "%d", test_name)
#define ASSERT_EQUALS_PTR(expected, actual, test_name) \
	ASSERT_AUX(expected, actual, expected, actual, "%p", test_name)
#define ASSERT_EQUALS_IPV4(expected, actual, test_name) \
	ASSERT_AUX(expected.s_addr, actual.s_addr, &expected, &actual, "%pI4", test_name)
#define ASSERT_NULL(actual, test_name) \
	ASSERT_AUX(NULL, actual, NULL, actual, "%p", test_name)

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
	return (failure_counter > 0) ? -EINVAL : 0;
