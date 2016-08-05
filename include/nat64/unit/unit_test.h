#ifndef _JOOL_UNIT_TEST_H
#define _JOOL_UNIT_TEST_H

#include "nat64/mod/common/types.h"
#include "nat64/mod/stateful/bib/entry.h"

#define ASSERT_PRIMITIVE(expected, actual, specifier, name, ...) ({	\
		/* don't want these to be evaluated multiple times. */	\
		typeof(expected) __expected = expected;			\
		typeof(expected) __actual = actual;			\
		if (__expected != __actual) {				\
			log_err("Test '" name "' failed.", ##__VA_ARGS__); \
			pr_err("  Expected: " specifier "\n", __expected);  \
			pr_err("  Actual  : " specifier "\n", __actual); \
		}							\
		__expected == __actual;					\
	})

/* https://www.kernel.org/doc/Documentation/printk-formats.txt */
#define ASSERT_UINT(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, actual, "%u", name, ##__VA_ARGS__)
#define ASSERT_INT(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, actual, "%d", name, ##__VA_ARGS__)
#define ASSERT_BOOL(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, actual, "%u", name, ##__VA_ARGS__)
#define ASSERT_ULONG(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, actual, "%lu", name, ##__VA_ARGS__)
#define ASSERT_U64(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, actual, "%llu", name, ##__VA_ARGS__)
#define ASSERT_PTR(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, actual, "%p", name, ##__VA_ARGS__)
#define ASSERT_BE16(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, be16_to_cpu(actual), "%u", name, \
				##__VA_ARGS__)
#define ASSERT_BE32(expected, actual, name, ...) \
		ASSERT_PRIMITIVE(expected, be32_to_cpu(actual), "%u", name, \
				##__VA_ARGS__)

/*
 * Ehh... there aren't macros, but they're still all caps so they're even
 * easier to recognize.
 */

bool ASSERT_ADDR4(const char *expected, const struct in_addr *actual,
		const char *test_name);
bool __ASSERT_ADDR4(const struct in_addr *expected,
		const struct in_addr *actual,
		const char *test_name);
bool ASSERT_TADDR4(const struct ipv4_transport_addr *expected,
		const struct ipv4_transport_addr *actual,
		const char *test_name);
bool ASSERT_ADDR6(const char *expected, const struct in6_addr *actual,
		const char *test_name);
bool __ASSERT_ADDR6(const struct in6_addr *expected,
		const struct in6_addr *actual,
		const char *test_name);
bool ASSERT_TADDR6(const struct ipv6_transport_addr *expected,
		const struct ipv6_transport_addr *actual,
		const char *test_name);
bool ASSERT_TUPLE(struct tuple *expected, struct tuple *actual,
		char *test_name);
bool ASSERT_BIB(struct bib_entry *expected, struct bib_entry *actual,
		char *test_name);
bool ASSERT_SESSION(struct session_entry *expected,
		struct session_entry *actual,
		char *test_name);

void print_session(struct session_entry *session);

bool init_full(void);
void end_full(void);

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
		log_info("Test '" test_name "': Success.\n", ##__VA_ARGS__);	\
	} else {														\
		log_info("Test '" test_name "': Failure.\n", ##__VA_ARGS__);	\
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

int broken_unit_call(const char *function);

#endif /* _JOOL_UNIT_TEST_H */
