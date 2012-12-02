/*
 * Macros to be used by test methods.
 */

#define ASSERT_AUX(expected, actual, printable_expected, printable_actual, specifier, test_name) \
	if ((expected) != (actual)) { \
		pr_warning("Test failed: %s Expected: " specifier ". Actual: " specifier ".\n", \
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
#define ASSERT_NOT_NULL(actual, test_name) \
	if ((actual) == NULL) { \
		pr_warning("Test failed: %s Expected: not NULL. Actual: NULL.\n", test_name); \
		return false; \
	}

#define END_TEST \
	return 0

/**
 * Macros to be used by the main function.
 */

#define START_TESTS(module_name)	\
	int test_counter = 0;			\
	int failure_counter = 0;		\
	pr_info("Module '%s': Starting tests...\n\n", module_name)

#define CALL_TEST(test, test_name)									\
	pr_info("Test '%s': Starting...\n", test_name);		\
	test_counter++;													\
	if (test) {														\
		pr_info("Test '%s': Success.\n\n", test_name);		\
	} else {														\
		pr_info("Test '%s': Failure.\n\n", test_name);		\
		failure_counter++;											\
	}

#define END_TESTS \
	pr_info("Finished. Runs: %d; Errors: %d\n", test_counter, failure_counter); \
	return (failure_counter > 0) ? -EINVAL : 0;
