#ifndef UNIT_TEST_H_
#define UNIT_TEST_H_

#include "nat64/comm/types.h"


/* TODO The UNIT_TESTING macro is a hack; remove it. */

bool assert_true(bool condition, char *test_name);
bool assert_equals_int(int expected, int actual, char *test_name);
bool assert_equals_u8(__u8 expected, __u8 actual, char *test_name);
bool assert_equals_u16(__u16 expected, __u16 actual, char *test_name);
bool assert_equals_u32(__u32 expected, __u32 actual, char *test_name);
bool assert_equals_ptr(void *expected, void *actual, char *test_name);
bool assert_equals_ipv4(struct in_addr *expected, struct in_addr *actual, char *test_name);
bool assert_equals_ipv4_str(unsigned char *expected_str, struct in_addr *actual, char *test_name);
bool assert_equals_ipv6(struct in6_addr *expected, struct in6_addr *actual, char *test_name);
bool assert_equals_ipv6_str(unsigned char *expected_str, struct in6_addr *actual, char *test_name);
bool assert_equals_csum(__sum16 expected, __sum16 actual, char *test_name);
bool assert_range(unsigned int expected_min, unsigned int expected_max, unsigned int actual,
		char *test_name);
bool assert_null(void *actual, char *test_name);

bool assert_false(bool condition, char *test_name);
bool assert_not_equals_int(int expected, int actual, char *test_name);
bool assert_not_equals_u16(__u16 expected, __u16 actual, char *test_name);
bool assert_not_equals_ptr(void *expected, void *actual, char *test_name);
bool assert_not_null(void *actual, char *test_name);

bool assert_equals_tuple(struct tuple *expected, struct tuple *actual, char *test_name);


/**
 * Macros to be used by the main test function.
 */
#define START_TESTS(module_name)	\
	int test_counter = 0;			\
	int failure_counter = 0;		\
	log_info("Module '%s': Starting tests...", module_name)

#define CALL_TEST(test, test_name, ...)								\
	log_info("Test '" test_name "': Starting...", ##__VA_ARGS__);	\
	test_counter++;													\
	if (test) {														\
		log_info("Test '" test_name "': Success.", ##__VA_ARGS__);	\
	} else {														\
		log_info("Test '" test_name "': Failure.", ##__VA_ARGS__);	\
		failure_counter++;											\
	}
#define INIT_CALL_END(init_function, test_function, end_function, test_name)	\
	if (!init_function)															\
		return -EINVAL;															\
	CALL_TEST(test_function, test_name)											\
	end_function
#define END_TESTS \
	log_info("Finished. Runs: %d; Errors: %d", test_counter, failure_counter); \
	return (failure_counter > 0) ? -EINVAL : 0;


#endif /* UNIT_TEST_H_ */
