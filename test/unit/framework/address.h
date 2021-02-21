#ifndef TEST_UNIT_FRAMEWORK_ADDRESS_H_
#define TEST_UNIT_FRAMEWORK_ADDRESS_H_

#include "common/types.h"

int str_to_addr4(const char *str, struct in_addr *result);
int str_to_addr6(const char *str, struct in6_addr *result);

int prefix6_parse(char *str, struct ipv6_prefix *result);
int prefix4_parse(char *str, struct ipv4_prefix *result);

#endif /* TEST_UNIT_FRAMEWORK_ADDRESS_H_ */
