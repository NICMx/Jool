//~ #include <stdbool.h>
//~ #include <stdio.h>


/**
 * Macros to be used by test methods.
 */
#define START_TEST	\
	int fails = 0;	

#define ASSERT_EQUALS(expected, actual, test_name) \
	if (expected != actual) { \
		pr_debug("Test failed: %s Expected: %d. Actual: %d.\n", test_name, expected, actual); \
		fails++; \
	}

#define END_TEST \
	return (fails == 0);

/**
 * Macros to be used by the main function.
 */
#define START_TESTS(module_name)	\
	int test_counter = 0;			\
	int failure_counter = 0;		\
	pr_debug("Module '%s': Starting tests...\n\n", module_name);

#define CALL_TEST(test, test_name)						\
	pr_debug("Test '%s': Starting...\n", test_name);	\
	test_counter++;										\
	if (test) {											\
		pr_debug("Test '%s': Success.\n\n", test_name);	\
	} else {											\
		pr_debug("Test '%s': Failure.\n\n", test_name);	\
		++failure_counter;								\
	}

#define END_TESTS \
	pr_debug("Finished. Runs: %d; Errors: %d\n", test_counter, failure_counter); \
	return -failure_counter;
