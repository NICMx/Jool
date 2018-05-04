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

struct test_group {
	char *name;

	/** To be run once per test group. */
	int (*setup_fn)(void);
	/** Reverts @setup_fn. */
	void (*teardown_fn)(void);
	/** To be run once per test. */
	int (*init_fn)(void);
	/** Reverts @init_fn. */
	void (*clean_fn)(void);

	unsigned int test_counter;
	unsigned int failure_counter;
};

int test_group_begin(struct test_group *group);
void test_group_test(struct test_group *group, bool (*test)(void), char *name);
int test_group_end(struct test_group *group);

int broken_unit_call(const char *function);

#endif /* _JOOL_UNIT_TEST_H */
